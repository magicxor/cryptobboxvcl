(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBAlgorithmIdentifier;

interface
uses
  Classes,
  SBConstants,
  SBASN1,
  SBASN1Tree,
  SBTypes,
  SBUtils,
  SBStrUtils;


type
  TElAlgorithmIdentifier =  class
   private 
    FAlgorithmOID : ByteArray;
    FAlgorithm : integer;

    procedure LoadParameters(Tag : TElASN1ConstrainedTag); virtual;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); virtual;

    function CheckAlgorithmOID(const OID : ByteArray) : boolean; virtual;
    
    procedure SetAlgorithm(Value : integer); virtual;
    procedure SetAlgorithmOID(const Value : ByteArray); virtual;

    function GetIsSignatureAlgorithm : boolean; virtual;
    function GetIsPublicKeyAlgorithm : boolean; virtual;
    function GetIsEncryptionAlgorithm : boolean; virtual;
    function GetIsHashAlgorithm : boolean; virtual;
    function GetSignatureHashAlgorithm : integer; virtual;
  public
    constructor Create;

    procedure Assign(Source: TElAlgorithmIdentifier); virtual;
    function Clone :  TElAlgorithmIdentifier; virtual ;
    function Equals(Algorithm : TElAlgorithmIdentifier) : boolean; {$ifdef D_12_UP}reintroduce; overload; {$endif} virtual;
    {$ifdef D_12_UP}
    function Equals(Obj: TObject): Boolean; overload; override;
     {$endif}

    class function CreateFromBuffer(Buffer : pointer; Size : integer) : TElAlgorithmIdentifier;
    class function CreateFromTag(Tag : TElASN1ConstrainedTag) : TElAlgorithmIdentifier;
    class function CreateByAlgorithm(Algorithm : integer) : TElAlgorithmIdentifier;
    class function CreateByAlgorithmOID(const OID : ByteArray) : TElAlgorithmIdentifier;
    function IsAlgorithmSupported(Algorithm : integer) : boolean; virtual;

    procedure LoadFromBuffer(Buffer : pointer; Size : integer); virtual;
    procedure SaveToBuffer(Buffer : pointer; var Size : integer); virtual;
    procedure LoadFromTag(Tag : TElASN1ConstrainedTag); virtual;
    procedure SaveToTag(Tag : TElASN1ConstrainedTag); virtual;
    function WriteParameters : ByteArray; virtual;

    property AlgorithmOID : ByteArray read FAlgorithmOID write SetAlgorithmOID;
    property Algorithm : integer read FAlgorithm write SetAlgorithm;
    property SignatureHashAlgorithm : integer read GetSignatureHashAlgorithm;
    property IsSignatureAlgorithm : boolean read GetIsSignatureAlgorithm;
    property IsPublicKeyAlgorithm : boolean read GetIsPublicKeyAlgorithm;
    property IsEncryptionAlgorithm : boolean read GetIsEncryptionAlgorithm;
    property IsHashAlgorithm : boolean read GetIsHashAlgorithm;
  end;

  TElRSAAlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    FHashAlgorithm : integer;

    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    procedure SetAlgorithmOID(const Value : ByteArray); override;
    procedure SetHashAlgorithm(Value : integer);
    function GetIsSignatureAlgorithm : boolean; override;
    function GetIsPublicKeyAlgorithm : boolean; override;
    function GetIsEncryptionAlgorithm : boolean; override;
    function GetSignatureHashAlgorithm : integer; override;    
  public
    constructor Create;
    procedure Assign(Source: TElAlgorithmIdentifier); override;    

    property HashAlgorithm : integer read FHashAlgorithm write SetHashAlgorithm;
  end;

  TElRSAPSSAlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    FHashAlgorithm : integer;
    FSaltSize : integer;
    FTrailerField : integer;
    FMGF : integer;
    FMGFHashAlgorithm : integer;

    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    function GetIsSignatureAlgorithm : boolean; override;
    function GetIsPublicKeyAlgorithm : boolean; override;
    function GetIsEncryptionAlgorithm : boolean; override;
    function GetSignatureHashAlgorithm : integer; override;    
  public
    constructor Create;
    procedure Assign(Source: TElAlgorithmIdentifier); override;

    property HashAlgorithm : integer read FHashAlgorithm write FHashAlgorithm;
    property SaltSize : integer read FSaltSize write FSaltSize;
    property TrailerField : integer read FTrailerField write FTrailerField;
    property MGF : integer read FMGF write FMGF;
    property MGFHashAlgorithm : integer read FMGFHashAlgorithm write FMGFHashAlgorithm;
  end;

  TElRSAOAEPAlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    FHashAlgorithm : integer;
    FMGF : integer;
    FMGFHashAlgorithm : integer;
    FStrLabel : string;
    FWriteDefaults : boolean;

    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    function GetIsSignatureAlgorithm : boolean; override;
    function GetIsPublicKeyAlgorithm : boolean; override;
    function GetIsEncryptionAlgorithm : boolean; override;       
  public
    constructor Create;
    procedure Assign(Source: TElAlgorithmIdentifier); override;
    
    property HashAlgorithm : integer read FHashAlgorithm write FHashAlgorithm;
    property MGF : integer read FMGF write FMGF;
    property MGFHashAlgorithm : integer read FMGFHashAlgorithm write FMGFHashAlgorithm;
    property StrLabel : string read FStrLabel write FStrLabel;
    property WriteDefaults : boolean read FWriteDefaults write FWriteDefaults;
  end;


  TElDSAAlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    FP : ByteArray;
    FQ : ByteArray;
    FG : ByteArray;

    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    function GetIsSignatureAlgorithm : boolean; override;
    function GetIsPublicKeyAlgorithm : boolean; override;
    function GetIsEncryptionAlgorithm : boolean; override;
    function GetSignatureHashAlgorithm : integer; override;

    procedure SetP(const V : ByteArray);    
    procedure SetQ(const V : ByteArray);
    procedure SetG(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Assign(Source: TElAlgorithmIdentifier); override;    

    property P: ByteArray read FP write SetP;
    property Q: ByteArray read FQ write SetQ;
    property G: ByteArray read FG write SetG;
  end;

  TElDHAlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    FP : ByteArray;
    FQ : ByteArray;
    FG : ByteArray;

    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    function GetIsSignatureAlgorithm : boolean; override;
    function GetIsPublicKeyAlgorithm : boolean; override;
    function GetIsEncryptionAlgorithm : boolean; override;

    procedure SetP(const V : ByteArray);    
    procedure SetQ(const V : ByteArray);
    procedure SetG(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Assign(Source: TElAlgorithmIdentifier); override;    

    property P: ByteArray read FP write SetP;
    property Q: ByteArray read FQ write SetQ;
    property G: ByteArray read FG write SetG;
  end;

  TElECAlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    FVersion : integer;
    FCurve : ByteArray;
    FFieldID : ByteArray;
    FFieldType : integer;
    FBasis : ByteArray;
    FM : integer;
    FK1 : integer;
    FK2 : integer;
    FK3 : integer;
    FHashAlgorithm : integer;
    FSpecifiedCurve : boolean;
    FCompressPoints : boolean;
    FHybridPoints : boolean;
    FImplicitCurve : boolean;
    FSeed : ByteArray;
    FP : ByteArray;
    FN : ByteArray;
    FH : integer;
    FA : ByteArray;
    FB : ByteArray;
    FX : ByteArray;
    FY : ByteArray;
    FBase : ByteArray;

    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    function GetIsSignatureAlgorithm : boolean; override;
    function GetIsPublicKeyAlgorithm : boolean; override;
    function GetIsEncryptionAlgorithm : boolean; override;

    procedure SetCurve(const V : ByteArray);
    procedure SetFieldID(const V : ByteArray);
    procedure SetBasis(const V : ByteArray);
    procedure SetSeed(const V : ByteArray);
    procedure SetP(const V : ByteArray);
    procedure SetN(const V : ByteArray);
    procedure SetA(const V : ByteArray);
    procedure SetB(const V : ByteArray);
    procedure SetX(const V : ByteArray);
    procedure SetY(const V : ByteArray);
    procedure SetBase(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Assign(Source: TElAlgorithmIdentifier); override;    

    property Version : integer read FVersion write FVersion;
    property Curve : ByteArray read FCurve write SetCurve;
    property FieldID : ByteArray read FFieldID write SetFieldID;
    property FieldType : integer read FFieldType write FFieldType;
    property Basis : ByteArray read FBasis write SetBasis;
    property M : integer read FM write FM;
    property K1 : integer read FK1 write FK1;
    property K2 : integer read FK2 write FK2;
    property K3 : integer read FK3 write FK3;
    property HashAlgorithm : integer read FHashAlgorithm write FHashAlgorithm;
    property SpecifiedCurve : boolean read FSpecifiedCurve write FSpecifiedCurve;
    property CompressPoints : boolean read FCompressPoints write FCompressPoints;
    property HybridPoints : boolean read FHybridPoints write FHybridPoints;
    property ImplicitCurve : boolean read FImplicitCurve write FImplicitCurve;

    property Seed : ByteArray read FSeed write SetSeed;
    property P: ByteArray read FP write SetP;
    property N: ByteArray read FN write SetN;
    property H: integer read FH write FH;
    property A: ByteArray read FA write SetA;
    property B: ByteArray read FB write SetB;
    property X: ByteArray read FX write SetX;
    property Y: ByteArray read FY write SetY;
    property Base: ByteArray read FBase write SetBase;
  end;

  TElECDSAAlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    FHashAlgorithm : integer;

    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    procedure SetAlgorithmOID(const Value : ByteArray); override;
    procedure SetHashAlgorithm(Value : integer);
    function GetIsSignatureAlgorithm : boolean; override;
    function GetIsPublicKeyAlgorithm : boolean; override;
    function GetIsEncryptionAlgorithm : boolean; override;
    function GetSignatureHashAlgorithm : integer; override;
  public
    constructor Create;
    procedure Assign(Source: TElAlgorithmIdentifier); override;

    property HashAlgorithm : integer read FHashAlgorithm write SetHashAlgorithm;
  end;


  {$ifdef SB_HAS_GOST}
  TElGOST3411AlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    procedure SetAlgorithmOID(const Value : ByteArray); override;
    function GetIsHashAlgorithm : boolean; override;
  public
    constructor Create;
    procedure Assign(Source: TElAlgorithmIdentifier); override;
  end;

  TElGOST3410AlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    FPublicKeyParamSet : ByteArray;
    FDigestParamSet : ByteArray;
    FEncryptionParamSet : ByteArray;

    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    procedure SetAlgorithmOID(const Value : ByteArray); override;
    function GetIsPublicKeyAlgorithm : boolean; override;
    procedure SetPublicKeyParamSet(const V : ByteArray);
    procedure SetDigestParamSet(const V : ByteArray);
    procedure SetEncryptionParamSet(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Assign(Source: TElAlgorithmIdentifier); override;

    property PublicKeyParamSet : ByteArray read FPublicKeyParamSet write SetPublicKeyParamSet;
    property DigestParamSet : ByteArray read FDigestParamSet write SetDigestParamSet;
    property EncryptionParamSet : ByteArray read FEncryptionParamSet write SetEncryptionParamSet;
  end;

  TElGOST3411WithGOST3410AlgorithmIdentifier =  class(TElAlgorithmIdentifier)
   private 
    procedure LoadParameters(Tag : TElASN1ConstrainedTag); override;
    procedure SaveParameters(Tag : TElASN1ConstrainedTag); override;
    function CheckAlgorithmOID(const OID : ByteArray) : boolean; override;

    function GetIsSignatureAlgorithm : boolean; override;
    function GetSignatureHashAlgorithm : integer; override;
  public
    constructor Create;
    procedure Assign(Source: TElAlgorithmIdentifier); override;
  end;
   {$endif}

  EElAlgorithmIdentifierError =  class(ESecureBlackboxError);
  
implementation

resourcestring
  SInvalidAlgorithmIdentifer = 'Invalid algorithm identifier';
  SUnknownAlgorithmIdentifier = 'Unknown algorithm identifier';
  SInvalidAlgorithmParameters = 'Invalid algorithm identifier parameters';
  SUnsupportedAlgorithmParameters = 'Unsupported algorithm parameters';
  SInvalidParameter = 'Invalid parameter';

{ some aux routines }
function ReadASN1TagData(Tag : TElASN1SimpleTag) : ByteArray;
begin
  if Length(Tag.Content) = 0 then
  begin
    Result := EmptyArray;
    Exit;
  end;

  if (Tag.TagId = SB_ASN1_INTEGER) and (Tag.Content[0] = byte(0)) then
  begin
    SetLength(Result, Length(Tag.Content) - 1);
    if Length(Result) > 0 then
      SBMove(Tag.Content, 1, Result, 0, Length(Result));
  end
  else
    Result := Tag.Content;
end;

procedure WriteASN1TagData(Tag : TElASN1SimpleTag; const Value : ByteArray);
var
  Content : ByteArray;
begin
  if Length(Value) = 0 then
  begin
    Tag.Content := EmptyArray;
    Exit;
  end;

  if (Tag.TagId = SB_ASN1_INTEGER) and (Value[0] >= $80) then
  begin
    SetLength(Content, Length(Value) + 1);
    Content[0] := 0;
    SBMove(Value, 0, Content, 1, Length(Value));
    Tag.Content := Content;
    ReleaseArray(Content);
  end
  else
    Tag.Content := Value;
end;


{ TElAlgorithmIdentifier }

constructor TElAlgorithmIdentifier.Create;
begin
  inherited;

  FAlgorithmOID := EmptyArray;
  FAlgorithm := SB_ALGORITHM_UNKNOWN;
end;

procedure TElAlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  if not (Source is TElAlgorithmIdentifier) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer)
  else
  begin
    FAlgorithmOID := CloneArray(Source.FAlgorithmOID);
    FAlgorithm := Source.FAlgorithm;
  end;  
end;

function TElAlgorithmIdentifier.Clone :  TElAlgorithmIdentifier ;
var
  Res : TElAlgorithmIdentifier;
begin;
  Res := TElAlgorithmIdentifier.CreateByAlgorithmOID(FAlgorithmOID);
  Res.Assign(Self);
  Result := Res;
end;

function TElAlgorithmIdentifier.Equals(Algorithm : TElAlgorithmIdentifier) : boolean;
var
  Buf1, Buf2 : ByteArray;
  Size1, Size2 : integer;
begin
  Size1 := 0;
  Size2 := 0;
  Self.SaveToBuffer(nil, Size1);
  Algorithm.SaveToBuffer(nil, Size2);
  SetLength(Buf1, Size1);
  SetLength(Buf2, Size2);
  Self.SaveToBuffer(@Buf1[0], Size1);
  Algorithm.SaveToBuffer(@Buf2[0], Size2);
  SetLength(Buf1, Size1);
  SetLength(Buf2, Size2);

  if Size1 <> Size2 then
  begin
    Result := false;
    Exit;
  end;

  Result := (Size1 > 0) and CompareMem(Buf1, 0, Buf2, 0, Size1);

  ReleaseArrays(Buf1, Buf2);
end;

{$ifdef D_12_UP}
function TElAlgorithmIdentifier.Equals(Obj: TObject): Boolean;
begin
  Result := inherited;
end;
 {$endif}

procedure TElAlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
begin
  if (Tag.Count <> 2) or (not Tag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
end;

procedure TElAlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
begin
  { writing NULL by default }
  Tag.AddField(false);
  Tag.GetField(1).TagId := SB_ASN1_NULL;
end;

function TElAlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := false;
end;

function TElAlgorithmIdentifier.GetIsSignatureAlgorithm : boolean;
begin
  Result := false;
end;

function TElAlgorithmIdentifier.GetIsPublicKeyAlgorithm : boolean;
begin
  Result := false;
end;

function TElAlgorithmIdentifier.GetIsEncryptionAlgorithm : boolean;
begin
  Result := false;
end;

function TElAlgorithmIdentifier.GetIsHashAlgorithm : boolean;
begin
  Result := false;
end;

function TElAlgorithmIdentifier.GetSignatureHashAlgorithm : integer;
begin
  Result := SB_ALGORITHM_UNKNOWN;
end;

procedure TElAlgorithmIdentifier.SetAlgorithm(Value : integer);
var
  OID : ByteArray; // NO NEED for ReleaseArray
begin
  OID := GetOIDByPKAlgorithm(Value);
  if Length(OID) = 0 then
    OID := GetOIDBySigAlgorithm(Value);

  SetAlgorithmOID(OID);
end;

procedure TElAlgorithmIdentifier.SetAlgorithmOID(const Value : ByteArray);
var
  Alg : integer;
begin
  if not CheckAlgorithmOID(Value) then
    Exit;

  Alg := GetPKAlgorithmByOID(Value);
  if (Alg = SB_ALGORITHM_UNKNOWN) then
    Alg := GetSigAlgorithmByOID(Value);

  FAlgorithmOID := CloneArray(Value);
  FAlgorithm := Alg;
end;

procedure TElAlgorithmIdentifier.LoadFromTag(Tag : TElASN1ConstrainedTag);
begin
  if (Tag.Count < 1) or (Tag.Count > 2) or (not Tag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer);

  if not CheckAlgorithmOID(TElASN1SimpleTag(Tag.GetField(0)).Content) then
    raise EElAlgorithmIdentifierError.Create(SUnknownAlgorithmIdentifier);

  AlgorithmOID := TElASN1SimpleTag(Tag.GetField(0)).Content;    
  LoadParameters(Tag);
end;

procedure TElAlgorithmIdentifier.LoadFromBuffer(Buffer : pointer; Size : integer);
var
  cTag : TElASN1ConstrainedTag;
begin
  cTag := TElASN1ConstrainedTag.CreateInstance;

  try
    if not cTag.LoadFromBuffer(Buffer , Size ) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer);

    if (cTag.Count < 1) or (not cTag.GetField(0).IsConstrained) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer);

    LoadFromTag(TElASN1ConstrainedTag(cTag.GetField(0)));
  finally
    FreeAndNil(cTag);
  end;
end;

procedure TElAlgorithmIdentifier.SaveToTag(Tag : TElASN1ConstrainedTag);
begin
  Tag.Clear;
  Tag.TagId := SB_ASN1_SEQUENCE;
  Tag.AddField(false);
  Tag.GetField(0).TagId := SB_ASN1_OBJECT;
  TElASN1SimpleTag(Tag.GetField(0)).Content := FAlgorithmOID;
  SaveParameters(Tag);
end;

function TElAlgorithmIdentifier.WriteParameters: ByteArray;
var
  Tag : TElASN1ConstrainedTag;
  Size : integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;

  try
    SaveToTag(Tag);

    if Tag.Count = 1 then
      Result := EmptyArray
    else
    begin
      Size := 0;
      Tag.GetField(1).SaveToBuffer(nil, Size);
      SetLength(Result, Size);
      Tag.GetField(1).SaveToBuffer(@Result[0], Size);
    end;  
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElAlgorithmIdentifier.SaveToBuffer(Buffer : pointer; var Size : integer);
var
  cTag : TElASN1ConstrainedTag;
begin
  cTag := TElASN1ConstrainedTag.CreateInstance;
  try
    SaveToTag(cTag);
    cTag.SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(cTag);
  end;
end;


class function TElAlgorithmIdentifier.CreateFromBuffer(Buffer : pointer; Size : integer) : TElAlgorithmIdentifier;
var
  cTag : TElASN1ConstrainedTag;
begin
  cTag := TElASN1ConstrainedTag.CreateInstance;
  Result := nil;

  try
    if not cTag.LoadFromBuffer(Buffer , Size ) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer);

    if (cTag.Count <> 1) or (not cTag.GetField(0).IsConstrained) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer);

    Result := CreateFromTag(TElASN1ConstrainedTag(cTag.GetField(0)));
  finally
    FreeAndNil(cTag);
  end;
end;

class function TElAlgorithmIdentifier.CreateFromTag(Tag : TElASN1ConstrainedTag) : TElAlgorithmIdentifier;
var
  OID : ByteArray; // NO NEED for ReleaseArray
begin
  if (Tag.Count < 1) or (Tag.Count > 2) or (not Tag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer);

  OID := TElASN1SimpleTag(Tag.GetField(0)).Content;

  { RSA OIDs}
  if CompareContent(OID, SB_OID_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_RSASIGNATURE_RIPEMD160) or
    CompareContent(OID, SB_OID_MD2_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_MD5_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION2) or
    CompareContent(OID, SB_OID_SHA1_RSA) or
    CompareContent(OID, SB_OID_SHA224_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA256_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA384_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA512_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_EA_RSA) or
    // some BAD implementations write incorrect signature algorithms
    CompareContent(OID, SB_OID_MD5)
  then
    Result := TElRSAAlgorithmIdentifier.Create
  { RSA-PSS }
  else if CompareContent(OID, SB_OID_RSAPSS) then
    Result := TElRSAPSSAlgorithmIdentifier.Create
  { RSA-OAEP }
  else if CompareContent(OID, SB_OID_RSAOAEP) then
    Result := TElRSAOAEPAlgorithmIdentifier.Create
  { DSA OIDs}
  else if (CompareContent(OID, SB_OID_DSA) or
    CompareContent(OID, SB_OID_DSA_SHA1) or
    CompareContent(OID, SB_OID_DSA_ALT) or
    CompareContent(OID, SB_OID_DSA_SHA1_ALT))
  then
    Result := TElDSAAlgorithmIdentifier.Create
  { DH OIDs}
  else if CompareContent(OID, SB_OID_DH) then
    Result := TElDHAlgorithmIdentifier.Create
  { EC OIDs}
  else if CompareContent(OID, SB_OID_EC_KEY) then
    Result := TElECAlgorithmIdentifier.Create
  { ECDSA OIDs}
  else if CompareContent(OID, SB_OID_ECDSA_SHA1) or
    CompareContent(OID, SB_OID_ECDSA_RECOMMENDED) or
    CompareContent(OID, SB_OID_ECDSA_SHA224) or
    CompareContent(OID, SB_OID_ECDSA_SHA256) or
    CompareContent(OID, SB_OID_ECDSA_SHA384) or
    CompareContent(OID, SB_OID_ECDSA_SHA512) or
    CompareContent(OID, SB_OID_ECDSA_SPECIFIED)
  then
    Result := TElECDSAAlgorithmIdentifier.Create
  { GOST OIDs}
  {$ifdef SB_HAS_GOST}
  else if CompareContent(OID, SB_OID_GOST_R3410_1994) or
    CompareContent(OID, SB_OID_GOST_R3410_2001)
  then
    Result := TElGOST3410AlgorithmIdentifier.Create
  else if CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994) or
    CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001)
  then
    Result := TElGOST3411WithGOST3410AlgorithmIdentifier.Create
   {$endif}  
  else
    raise EElAlgorithmIdentifierError.Create(SUnknownAlgorithmIdentifier);

  if Assigned(Result) then
    Result.LoadFromTag(Tag);
end;

class function TElAlgorithmIdentifier.CreateByAlgorithm(Algorithm : integer) : TElAlgorithmIdentifier;
var
  OID : ByteArray;
begin
  OID := GetOIDByPKAlgorithm(Algorithm);
  if Length(OID) = 0 then
    OID := GetOIDBySigAlgorithm(Algorithm);
  Result := CreateByAlgorithmOID(OID);
end;

class function TElAlgorithmIdentifier.CreateByAlgorithmOID(const OID : ByteArray) : TElAlgorithmIdentifier;
begin
  { RSA OIDs}
  if CompareContent(OID, SB_OID_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_RSASIGNATURE_RIPEMD160) or
    CompareContent(OID, SB_OID_MD2_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_MD5_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION2) or
    CompareContent(OID, SB_OID_SHA1_RSA) or
    CompareContent(OID, SB_OID_SHA224_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA256_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA384_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA512_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_EA_RSA)
  then
    Result := TElRSAAlgorithmIdentifier.Create
  { RSA-PSS }
  else if CompareContent(OID, SB_OID_RSAPSS) then
    Result := TElRSAPSSAlgorithmIdentifier.Create
  { RSA-OAEP }
  else if CompareContent(OID, SB_OID_RSAOAEP) then
    Result := TElRSAOAEPAlgorithmIdentifier.Create
  { DSA OIDs}
  else if (CompareContent(OID, SB_OID_DSA) or
    CompareContent(OID, SB_OID_DSA_SHA1) or
    CompareContent(OID, SB_OID_DSA_ALT) or
    CompareContent(OID, SB_OID_DSA_SHA1_ALT))
  then
    Result := TElDSAAlgorithmIdentifier.Create
  { DH OIDs}
  else if CompareContent(OID, SB_OID_DH) then
    Result := TElDHAlgorithmIdentifier.Create
  { EC OIDs}
  else if CompareContent(OID, SB_OID_EC_KEY) then
    Result := TElECAlgorithmIdentifier.Create
  { ECDSA OIDs}
  else if CompareContent(OID, SB_OID_ECDSA_SHA1) or
    CompareContent(OID, SB_OID_ECDSA_RECOMMENDED) or
    CompareContent(OID, SB_OID_ECDSA_SHA224) or
    CompareContent(OID, SB_OID_ECDSA_SHA256) or
    CompareContent(OID, SB_OID_ECDSA_SHA384) or
    CompareContent(OID, SB_OID_ECDSA_SHA512) or
    CompareContent(OID, SB_OID_ECDSA_SPECIFIED)
  then
    Result := TElECDSAAlgorithmIdentifier.Create
  { GOST OIDs}
  {$ifdef SB_HAS_GOST}
  else if CompareContent(OID, SB_OID_GOST_R3410_1994) or
    CompareContent(OID, SB_OID_GOST_R3410_2001)
  then
    Result := TElGOST3410AlgorithmIdentifier.Create
  else if CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994) or
    CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001)
  then
    Result := TElGOST3411WithGOST3410AlgorithmIdentifier.Create
   {$endif}  
  else
    raise EElAlgorithmIdentifierError.Create(SUnknownAlgorithmIdentifier);

  Result.AlgorithmOID := OID;
end;

function TElAlgorithmIdentifier.IsAlgorithmSupported(Algorithm : integer) : boolean;
var
  OID : ByteArray;
begin
  OID := GetOIDByAlgorithm(Algorithm);
  if Length(OID) = 0 then
    OID := GetOIDBySigAlgorithm(Algorithm);
  Result := CheckAlgorithmOID(OID);
end;

{ TElRSAAlgorithmIdentifier }

constructor TElRSAAlgorithmIdentifier.Create;
begin
  inherited;

  AlgorithmOID := SB_OID_RSAENCRYPTION;
end;

procedure TElRSAAlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;
  
  if not (Source is TElRSAAlgorithmIdentifier) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer)
  else
  begin
    FHashAlgorithm := TElRSAAlgorithmIdentifier(Source).FHashAlgorithm;
  end;
end;

procedure TElRSAAlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
begin
  { expecting NULL or INTEGER for id-ea-rsa }
  if Tag.Count = 1 then Exit;

  if (Tag.Count > 2) or (not (Tag.GetField(1).CheckType(SB_ASN1_NULL, false) or
    Tag.GetField(1).CheckType(SB_ASN1_INTEGER, false)))
  then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
end;

function TElRSAAlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_EA_RSA) or
    CompareContent(OID, SB_OID_MD2_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_MD5_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION2) or
    CompareContent(OID, SB_OID_SHA1_RSA) or
    CompareContent(OID, SB_OID_SHA224_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA256_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA384_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA512_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_RSASIGNATURE_RIPEMD160) or
    // some incorrect implementations write incorrect object identifiers
    // (hash OIDs instead of RSA signature OIDs)
    CompareContent(OID, SB_OID_MD5);
end;

procedure TElRSAAlgorithmIdentifier.SetAlgorithmOID(const Value : ByteArray);
begin
  inherited;

  case Algorithm of
    SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION :
      FHashAlgorithm := SB_ALGORITHM_UNKNOWN;
    SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION :
      FHashAlgorithm := SB_ALGORITHM_DGST_MD2;
    SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION :
      FHashAlgorithm := SB_ALGORITHM_DGST_MD5;
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
    SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA224;
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA256;
    SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA384;
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA512;
    SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160 :
      FHashAlgorithm := SB_ALGORITHM_DGST_RIPEMD160
  else
    FHashAlgorithm := SB_ALGORITHM_UNKNOWN;
  end;  
end;

procedure TElRSAAlgorithmIdentifier.SetHashAlgorithm(Value : integer);
begin
  FHashAlgorithm := Value;

  case FHashAlgorithm of
    SB_ALGORITHM_DGST_MD2 :
      Algorithm := SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION;
    SB_ALGORITHM_DGST_MD5 :
      Algorithm := SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION;
    SB_ALGORITHM_DGST_SHA1 :
      Algorithm := SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION;
    SB_ALGORITHM_DGST_SHA224 :
      Algorithm := SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION;
    SB_ALGORITHM_DGST_SHA256 :
      Algorithm := SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION;
    SB_ALGORITHM_DGST_SHA384 :
      Algorithm := SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION;
    SB_ALGORITHM_DGST_SHA512 :
      Algorithm := SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION;
    SB_ALGORITHM_DGST_RIPEMD160 :
      Algorithm := SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160
  else
    begin
      FHashAlgorithm := SB_ALGORITHM_UNKNOWN;
      Algorithm := SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION;
    end;  
  end;
end;

function TElRSAAlgorithmIdentifier.GetIsSignatureAlgorithm : boolean;
begin
  Result := true;
end;

function TElRSAAlgorithmIdentifier.GetIsPublicKeyAlgorithm : boolean;
begin
  Result := (Algorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION);
end;

function TElRSAAlgorithmIdentifier.GetIsEncryptionAlgorithm : boolean;
begin
  Result := true;
end;

function TElRSAAlgorithmIdentifier.GetSignatureHashAlgorithm : integer;
begin
  Result := HashAlgorithm;
end;


{ TElECAlgorithmIdentifier }

constructor TElECAlgorithmIdentifier.Create;
begin
  inherited;

  FVersion := 1;
  FCurve := EmptyArray;
  FFieldID := EmptyArray;
  FFieldType := SB_EC_FLD_TYPE_UNKNOWN;
  FBasis := EmptyArray;
  FM := 0;
  FK1 := 0;
  FK2 := 0;
  FK3 := 0;
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FSpecifiedCurve := false;
  FCompressPoints := false;
  FHybridPoints := false;
  FImplicitCurve := false;
  FSeed := EmptyArray;
  FP := EmptyArray;
  FN := EmptyArray;
  FH := 0;
  FA := EmptyArray;
  FB := EmptyArray;
  FX := EmptyArray;
  FY := EmptyArray;
  FBase := EmptyArray;

  AlgorithmOID := SB_OID_EC_KEY;
end;

 destructor  TElECAlgorithmIdentifier.Destroy;
begin
  ReleaseArray(FCurve);
  ReleaseArray(FFieldID);
  ReleaseArray(FBasis);
  ReleaseArray(FSeed);
  ReleaseArray(FP);
  ReleaseArray(FN);
  ReleaseArray(FA);
  ReleaseArray(FB);
  ReleaseArray(FX);
  ReleaseArray(FY);
  ReleaseArray(FBase);
  inherited;
end;

procedure TElECAlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;

  if not (Source is TElECAlgorithmIdentifier) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer)
  else
  begin
    FVersion := TElECAlgorithmIdentifier(Source).FVersion;
    FCurve := CloneArray(TElECAlgorithmIdentifier(Source).FCurve);
    FFieldID := CloneArray(TElECAlgorithmIdentifier(Source).FFieldID);
    FFieldType := TElECAlgorithmIdentifier(Source).FFieldType;
    FBasis := CloneArray(TElECAlgorithmIdentifier(Source).FBasis);
    FM := TElECAlgorithmIdentifier(Source).FM;
    FK1 := TElECAlgorithmIdentifier(Source).FK1;
    FK2 := TElECAlgorithmIdentifier(Source).FK2;
    FK3 := TElECAlgorithmIdentifier(Source).FK3;
    FHashAlgorithm := TElECAlgorithmIdentifier(Source).FHashAlgorithm;
    FSpecifiedCurve := TElECAlgorithmIdentifier(Source).FSpecifiedCurve;
    FCompressPoints := TElECAlgorithmIdentifier(Source).FCompressPoints;
    FHybridPoints := TElECAlgorithmIdentifier(Source).FHybridPoints;
    FImplicitCurve := TElECAlgorithmIdentifier(Source).FImplicitCurve;
    FSeed := CloneArray(TElECAlgorithmIdentifier(Source).FSeed);
    FP := CloneArray(TElECAlgorithmIdentifier(Source).FP);
    FN := CloneArray(TElECAlgorithmIdentifier(Source).FN);
    FH := TElECAlgorithmIdentifier(Source).FH;
    FA := CloneArray(TElECAlgorithmIdentifier(Source).FA);
    FB := CloneArray(TElECAlgorithmIdentifier(Source).FB);
    FX := CloneArray(TElECAlgorithmIdentifier(Source).FX);
    FY := CloneArray(TElECAlgorithmIdentifier(Source).FY);
    FBase := CloneArray(TElECAlgorithmIdentifier(Source).FBase);
  end;
end;

procedure TElECAlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
var
  cTag : TElASN1ConstrainedTag;
  i : integer;
  FieldID : ByteArray;
begin
  SetLength(FieldID, 0);
  if Tag.Count < 2 then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

  if Tag.GetField(1).CheckType(SB_ASN1_OBJECT, false) then
  begin
    // named curve
    FCurve := TElASN1SimpleTag(Tag.GetField(1)).Content;
    FSpecifiedCurve := false;
    FImplicitCurve := false;
  end
  else if Tag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true) then
  begin
    // specified curve
    cTag := TElASN1ConstrainedTag(Tag.GetField(1));

    if (cTag.Count < 5) or (not cTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) or
      (not cTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not cTag.GetField(2).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not cTag.GetField(3).CheckType(SB_ASN1_OCTETSTRING, false)) or
      (not cTag.GetField(4).CheckType(SB_ASN1_INTEGER, false))
    then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    FSpecifiedCurve := true;
    FImplicitCurve := false;

    // version
    FVersion := ASN1ReadInteger(TElASN1SimpleTag(cTag.GetField(0)));

    if (FVersion < 1) or (FVersion > 3) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    if not cTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    cTag := TElASN1ConstrainedTag(cTag.GetField(1));
    // fieldID
    if (cTag.Count <> 2) or (not cTag.GetField(0).CheckType(SB_ASN1_OBJECT, false))  then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    FieldID := TElASN1SimpleTag(cTag.GetField(0)).Content;
    if CompareContent(FieldID, SB_OID_FLD_TYPE_FP) then
    begin
      // prime-field
      if not cTag.GetField(1).CheckType(SB_ASN1_INTEGER, false) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      FP := TrimLeadingZeros(TElASN1SimpleTag(cTag.GetField(1)).Content);
      FFieldType := SB_EC_FLD_TYPE_FP;
    end
    else if CompareContent(FieldID, SB_OID_FLD_TYPE_F2M) then
    begin
      // characteristic-two-field
      if (not cTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true))
      then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      cTag := TElASN1ConstrainedTag(cTag.GetField(1));

      if (cTag.Count <> 3) or (not cTag.GetField(0).CheckType(SB_ASN1_INTEGER, false))
        or (not cTag.GetField(1).CheckType(SB_ASN1_OBJECT, false))
      then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      FM := ASN1ReadInteger(TElASN1SimpleTag(cTag.GetField(0)));

      if CompareContent(TElASN1SimpleTag(cTag.GetField(1)).Content, SB_OID_FLD_BASIS_N) then
      begin
        // normal basis - not supported for now
        raise EElAlgorithmIdentifierError.Create(SUnsupportedAlgorithmParameters);
      end
      else if CompareContent(TElASN1SimpleTag(cTag.GetField(1)).Content, SB_OID_FLD_BASIS_T) then
      begin
        // trinomial basis
        if not cTag.GetField(2).CheckType(SB_ASN1_INTEGER, false) then
          raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

        FP := EmptyArray;
        FK1 := ASN1ReadInteger(TElASN1SimpleTag(cTag.GetField(2)));
        FK2 := 0;
        FK3 := 0;
        FFieldType := SB_EC_FLD_TYPE_F2MP;
      end
      else if CompareContent(TElASN1SimpleTag(cTag.GetField(1)).Content, SB_OID_FLD_BASIS_P) then
      begin
        // pentanomial basis
        if not cTag.GetField(2).CheckType(SB_ASN1_SEQUENCE, true) then
          raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

        cTag := TElASN1ConstrainedTag(cTag.GetField(2));

        if (cTag.Count < 3) or (not cTag.GetField(0).CheckType(SB_ASN1_INTEGER, false))
          or (not cTag.GetField(1).CheckType(SB_ASN1_INTEGER, false))
          or (not cTag.GetField(2).CheckType(SB_ASN1_INTEGER, false))
        then
          raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

        FP := EmptyArray;

        FK1 := ASN1ReadInteger(TElASN1SimpleTag(cTag.GetField(0)));
        FK2 := ASN1ReadInteger(TElASN1SimpleTag(cTag.GetField(1)));
        FK3 := ASN1ReadInteger(TElASN1SimpleTag(cTag.GetField(2)));

        if not((K1 > 0) and (K2 > K1) and (K3 > K2)) then
          raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

        FFieldType := SB_EC_FLD_TYPE_F2MP;
      end
      else
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
    end
    else
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    // curve
    cTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(2));
    if (cTag.Count < 2) or (cTag.Count > 3) or (not cTag.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false))
      or (not cTag.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false))
    then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    if (Version > 1) and (cTag.Count <> 3) then
       raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    if (cTag.Count = 3) and (not cTag.GetField(2).CheckType(SB_ASN1_BITSTRING, false)) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    FA := TElASN1SimpleTag(cTag.GetField(0)).Content;
    FB := TElASN1SimpleTag(cTag.GetField(1)).Content;
    if cTag.Count = 3 then
      Seed := TElASN1SimpleTag(cTag.GetField(2)).Content;

    cTag := TElASN1ConstrainedTag(Tag.GetField(1));
    // base
    FBase := TElASN1SimpleTag(cTag.GetField(3)).Content;

    // order
    FN := TrimLeadingZeros(TElASN1SimpleTag(cTag.GetField(4)).Content);

    // other OPTIONAL fields
    for i := 5 to cTag.Count - 1 do
    begin
      if cTag.GetField(i).CheckType(SB_ASN1_INTEGER, false) then
      begin
        // cofactor
        FH := ASN1ReadInteger(TElASN1SimpleTag(cTag.GetField(i)));
      end
      else if cTag.GetField(i).CheckType(SB_ASN1_SEQUENCE, true) then
      begin
        // hash algorithm
        if (TElASN1ConstrainedTag(cTag.GetField(i)).Count > 0) and
          (TElASN1ConstrainedTag(cTag.GetField(i)).GetField(0).CheckType(SB_ASN1_OBJECT, false))
        then
          FHashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(TElASN1ConstrainedTag(cTag.GetField(i)).GetField(0)).Content)
      end
      else
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
    end;
  end
  else
  if Tag.GetField(1).CheckType(SB_ASN1_NULL, false) then
  begin
    { implicit curve }
    FImplicitCurve := true;
    FSpecifiedCurve := false;
  end
  else
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
end;

procedure TElECAlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
var
  cTag, subTag: TElASN1ConstrainedTag;
begin
  if FImplicitCurve then
  begin
    Tag.AddField(false);
    Tag.GetField(1).TagId := SB_ASN1_NULL;
  end
  else if (not FSpecifiedCurve) and (Length(FCurve) > 0) then
  begin
    Tag.AddField(false);
    Tag.GetField(1).TagId := SB_ASN1_OBJECT;
    TElASN1SimpleTag(Tag.GetField(1)).Content := FCurve;
  end
  else
  begin
    Tag.AddField(true);
    Tag.GetField(1).TagId := SB_ASN1_SEQUENCE;
    cTag := TElASN1ConstrainedTag(Tag.GetField(1));
    { version }
    cTag.AddField(false);
    asn1WriteInteger(TElASN1SimpleTag(cTag.GetField(0)), 1);
    { fieldID }
    cTag.AddField(true);
    subTag := TElASN1ConstrainedTag(cTag.GetField(1));
    subTag.TagId := SB_ASN1_SEQUENCE;
    { fieldID.fieldType }
    subTag.AddField(False);
    TElASN1SimpleTag(subTag.GetField(0)).TagId := SB_ASN1_OBJECT;
    if FieldType = SB_EC_FLD_TYPE_FP then
    begin
      TElASN1SimpleTag(subTag.GetField(0)).Content := SB_OID_FLD_TYPE_FP;
      { fieldID.Prime-p }
      subTag.AddField(false);
      TElASN1SimpleTag(subTag.GetField(1)).TagId := SB_ASN1_INTEGER;
      TElASN1SimpleTag(subTag.GetField(1)).Content := FP;
    end
    else if FieldType = SB_EC_FLD_TYPE_F2MP then
    begin
      TElASN1SimpleTag(subTag.GetField(0)).Content := SB_OID_FLD_TYPE_F2M;
      { FieldID.Characteristic-two }
      subTag.AddField(true);
      subTag.GetField(1).TagId := SB_ASN1_SEQUENCE;
      subTag := TElASN1ConstrainedTag(subTag.GetField(1));
      { FieldID.Characteristic-two.M}
      subTag.AddField(false);
      ASN1WriteInteger(TElASN1SimpleTag(subTag.GetField(0)), FM);
      { FieldID.Characteristic-two.basis }
      subTag.AddField(false);
      subTag.GetField(1).TagId := SB_ASN1_OBJECT;

      if (K2 = 0) or (K3 = 0) then
      begin
        { trinomial basis }
        TElASN1SimpleTag(subTag.GetField(1)).Content := SB_OID_FLD_BASIS_T;
        subTag.AddField(false);
        ASN1WriteInteger(TElASN1SimpleTag(subTag.GetField(2)), FK1);
      end
      else
      begin
        { pentanomial basis }
        TElASN1SimpleTag(subTag.GetField(1)).Content := SB_OID_FLD_BASIS_P;
        subTag.AddField(true);
        subTag.GetField(2).TagId := SB_ASN1_SEQUENCE;
        subTag := TElASN1ConstrainedTag(subTag.GetField(2));
        subTag.AddField(false);
        subTag.AddField(false);
        subTag.AddField(false);
        ASN1WriteInteger(TElASN1SimpleTag(subTag.GetField(0)), FK1);
        ASN1WriteInteger(TElASN1SimpleTag(subTag.GetField(1)), FK2);
        ASN1WriteInteger(TElASN1SimpleTag(subTag.GetField(2)), FK3);
      end;
    end
    else
      Exit;

    { curve }
    cTag.AddField(true);
    cTag.GetField(2).TagId := SB_ASN1_SEQUENCE;
    subTag := TElASN1ConstrainedTag(cTag.GetField(2));
    { curve.A }
    subTag.AddField(false);
    subTag.GetField(0).TagId := SB_ASN1_OCTETSTRING;
    TElASN1SimpleTag(subTag.GetField(0)).Content := (FA);
    { curve.B }
    subTag.AddField(false);
    subTag.GetField(1).TagId := SB_ASN1_OCTETSTRING;
    TElASN1SimpleTag(subTag.GetField(1)).Content := (FB);
    { curve.Seed}
    if Length(Seed) > 0 then
    begin
      subTag.AddField(false);
      subTag.GetField(2).TagId := SB_ASN1_OCTETSTRING;
      TElASN1SimpleTag(subTag.GetField(2)).Content := (FSeed);
    end;

    { base }
    cTag.AddField(false);
    TElASN1SimpleTag(cTag.GetField(3)).TagId := SB_ASN1_OCTETSTRING;
    TElASN1SimpleTag(cTag.GetField(3)).Content := (FBase);

    { order }
    cTag.AddField(false);
    TElASN1SimpleTag(cTag.GetField(4)).TagId := SB_ASN1_INTEGER;
    TElASN1SimpleTag(cTag.GetField(4)).Content := (FN);

    { cofactor }
    if H > 0 then
    begin
      cTag.AddField(false);
      asn1WriteInteger(TElASN1SimpleTag(cTag.GetField(5)), FH);
    end;

    { hash algorithm, if present}
    if (FHashAlgorithm <> SB_ALGORITHM_UNKNOWN) then
    begin
      cTag.AddField(true);
      TElASN1ConstrainedTag(cTag.GetField(6)).TagId := SB_ASN1_SEQUENCE;
      TElASN1ConstrainedTag(cTag.GetField(6)).AddField(false);
      TElASN1ConstrainedTag(cTag.GetField(6)).AddField(false);

      TElASN1SimpleTag(TElASN1ConstrainedTag(cTag.GetField(6)).GetField(0)).TagId := SB_ASN1_OBJECT;
      TElASN1SimpleTag(TElASN1ConstrainedTag(cTag.GetField(6)).GetField(0)).Content := GetOIDByHashAlgorithm(FHashAlgorithm);
      TElASN1SimpleTag(TElASN1ConstrainedTag(cTag.GetField(6)).GetField(1)).TagId := SB_ASN1_NULL;
    end;
  end;
end;

function TElECAlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_EC_KEY);
end;

function TElECAlgorithmIdentifier.GetIsSignatureAlgorithm : boolean;
begin
  Result := false;
end;

function TElECAlgorithmIdentifier.GetIsPublicKeyAlgorithm : boolean;
begin
  Result := true;
end;

function TElECAlgorithmIdentifier.GetIsEncryptionAlgorithm : boolean;
begin
  Result := false;
end;

procedure TElECAlgorithmIdentifier.SetCurve(const V : ByteArray);
begin
  FCurve := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetFieldID(const V : ByteArray);
begin
  FFieldID := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetBasis(const V : ByteArray);
begin
  FBasis := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetSeed(const V : ByteArray);
begin
  FSeed := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetP(const V : ByteArray);
begin
  FP := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetN(const V : ByteArray);
begin
  FN := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetA(const V : ByteArray);
begin
  FA := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetB(const V : ByteArray);
begin
  FB := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetX(const V : ByteArray);
begin
  FX := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetY(const V : ByteArray);
begin
  FY := CloneArray(V);
end;

procedure TElECAlgorithmIdentifier.SetBase(const V : ByteArray);
begin
  FBase := CloneArray(V);
end;

{ TElECDSAAlgorithmIdentifier }

constructor TElECDSAAlgorithmIdentifier.Create;
begin
  inherited;

  AlgorithmOID := SB_OID_ECDSA_SHA1;
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
end;

procedure TElECDSAAlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;

  if not (Source is TElECDSAAlgorithmIdentifier) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer)
  else
  begin
    FHashAlgorithm := TElECDSAAlgorithmIdentifier(Source).FHashAlgorithm;
  end;
end;  

procedure TElECDSAAlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
begin
  if CompareContent(FAlgorithmOID, SB_OID_ECDSA_SPECIFIED) then
  begin
    if (Tag.Count < 2) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    if Tag.GetField(1).CheckType(SB_ASN1_OBJECT, false) then
      FHashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(Tag.GetField(1)).Content)
    else if Tag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true) and
      (TElASN1ConstrainedTag(Tag.GetField(1)).Count = 1) and
      (TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).CheckType(SB_ASN1_OBJECT, false))
    then
      FHashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).Content)
    else
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
  end
  else
  begin
    if (Tag.Count = 2) and (not Tag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
  end;
end;

procedure TElECDSAAlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
begin
  Tag.AddField(false);

  if CompareContent(FAlgorithmOID, SB_OID_ECDSA_SPECIFIED) then
  begin
    Tag.GetField(1).TagId := SB_ASN1_OBJECT;
    TElASN1SimpleTag(Tag.GetField(1)).Content := GetOIDByHashAlgorithm(FHashAlgorithm);
  end
  else
    Tag.GetField(1).TagId := SB_ASN1_NULL;
end;

function TElECDSAAlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_ECDSA_SHA1) or
    CompareContent(OID, SB_OID_ECDSA_SHA224) or
    CompareContent(OID, SB_OID_ECDSA_SHA256) or
    CompareContent(OID, SB_OID_ECDSA_SHA384) or
    CompareContent(OID, SB_OID_ECDSA_SHA512) or
    CompareContent(OID, SB_OID_ECDSA_RECOMMENDED) or
    CompareContent(OID, SB_OID_ECDSA_SPECIFIED);
end;

procedure TElECDSAAlgorithmIdentifier.SetAlgorithmOID(const Value : ByteArray);
begin
  inherited;

  case Algorithm of
    SB_CERT_ALGORITHM_SHA1_ECDSA :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
    SB_CERT_ALGORITHM_SHA224_ECDSA :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA224;
    SB_CERT_ALGORITHM_SHA256_ECDSA :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA256;
    SB_CERT_ALGORITHM_SHA384_ECDSA :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA384;
    SB_CERT_ALGORITHM_SHA512_ECDSA :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA512;
    SB_CERT_ALGORITHM_SPECIFIED_ECDSA :
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  else
    FHashAlgorithm := SB_ALGORITHM_UNKNOWN;
  end;
end;

procedure TElECDSAAlgorithmIdentifier.SetHashAlgorithm(Value : integer);
begin
  FHashAlgorithm := Value;

  if Algorithm = SB_CERT_ALGORITHM_SPECIFIED_ECDSA then
    Exit;

  case FHashAlgorithm of
    SB_ALGORITHM_DGST_SHA1 :
      Algorithm := SB_CERT_ALGORITHM_SHA1_ECDSA;
    SB_ALGORITHM_DGST_SHA224 :
      Algorithm := SB_CERT_ALGORITHM_SHA224_ECDSA;
    SB_ALGORITHM_DGST_SHA256 :
      Algorithm := SB_CERT_ALGORITHM_SHA256_ECDSA;
    SB_ALGORITHM_DGST_SHA384 :
      Algorithm := SB_CERT_ALGORITHM_SHA384_ECDSA;
    SB_ALGORITHM_DGST_SHA512 :
      Algorithm := SB_CERT_ALGORITHM_SHA512_ECDSA;
  else
    begin
      FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
      AlgorithmOID := SB_OID_ECDSA_SHA1;
    end  
  end;
end;

function TElECDSAAlgorithmIdentifier.GetIsSignatureAlgorithm : boolean;
begin
  Result := true;
end;

function TElECDSAAlgorithmIdentifier.GetIsPublicKeyAlgorithm : boolean;
begin
  Result := false;
end;

function TElECDSAAlgorithmIdentifier.GetIsEncryptionAlgorithm : boolean;
begin
  Result := false;
end;

function TElECDSAAlgorithmIdentifier.GetSignatureHashAlgorithm : integer;
begin
  Result := HashAlgorithm;
end;


{ TElRSAPSSAlgorithmIdentifier }

constructor TElRSAPSSAlgorithmIdentifier.Create;
begin
  inherited;

  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FSaltSize := 20;
  FTrailerField := 1;
  FMGF := SB_CERT_MGF1;
  FMGFHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FAlgorithm := SB_CERT_ALGORITHM_ID_RSAPSS;
  FAlgorithmOID := SB_OID_RSAPSS;
end;

procedure TElRSAPSSAlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;

  if (Source is TElRSAAlgorithmIdentifier) then
  begin
    FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
    FSaltSize := 20;
    FTrailerField := 1;
    FMGF := SB_CERT_MGF1;
    FMGFHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  end
  else if (Source is TElRSAPSSAlgorithmIdentifier) then
  begin
    FHashAlgorithm := TElRSAPSSAlgorithmIdentifier(Source).FHashAlgorithm;
    FSaltSize := TElRSAPSSAlgorithmIdentifier(Source).FSaltSize;
    FTrailerField := TElRSAPSSAlgorithmIdentifier(Source).FTrailerField;
    FMGF := TElRSAPSSAlgorithmIdentifier(Source).FMGF;
    FMGFHashAlgorithm := TElRSAPSSAlgorithmIdentifier(Source).FMGFHashAlgorithm;
  end
  else
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer);
end;

procedure TElRSAPSSAlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
var
  STag, ATag : TElASN1ConstrainedTag;
  Index, TagNum : integer;
begin
  { setting default parameters }
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FSaltSize := 20;
  FTrailerField := 1;
  FMGF := SB_CERT_MGF1;
  FMGFHashAlgorithm := SB_ALGORITHM_DGST_SHA1;

  if Tag.GetField(1).CheckType(SB_ASN1_NULL, false) then
    Exit; // default parameters used

  if not Tag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

  STag := TElASN1ConstrainedTag(Tag.GetField(1));
  if STag.Count > 4 then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

  Index := 0;
  TagNum := 0;

  while (Index < 4) and (TagNum < STag.Count) do
  begin
    if not STag.GetField(TagNum).IsConstrained then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    ATag := TElASN1ConstrainedTag(STag.GetField(TagNum));
    Inc(TagNum);

    if (ATag.Count <> 1) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    if (ATag.TagId = SB_ASN1_A0) then
    begin
      { hash algorithm }
      if (Index > 0) or (not ATag.GetField(0).IsConstrained) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      ATag := TElASN1ConstrainedTag(ATag.GetField(0));

      if (ATag.Count > 2) or (ATag.Count < 1) or
        (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false))
      then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      if (ATag.Count > 1) and (not ATag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      FHashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(ATag.GetField(0)).Content);

      Index := 1;
    end
    else
    if (ATag.TagId = SB_ASN1_A1) then
    begin
      { MGF }
      if (Index > 1) or (not ATag.GetField(0).IsConstrained) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      ATag := TElASN1ConstrainedTag(ATag.GetField(0));
      if (ATag.Count <> 2) or
        (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
        (not ATag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true))
      then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      if not CompareContent(TElASN1SimpleTag(ATag.GetField(0)).Content, SB_OID_MGF1)
      then
        raise EElAlgorithmIdentifierError.Create(SUnsupportedAlgorithmParameters);

      ATag := TElASN1ConstrainedTag(ATag.GetField(1));

      if (ATag.Count > 2) or (ATag.Count < 1) or (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      if (ATag.Count > 1) and (not ATag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      FMGFHashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(ATag.GetField(0)).Content);

      Index := 2;
    end
    else
    if ATag.TagId = SB_ASN1_A2 then
    begin
      { Salt size }
      if (Index > 2) or (not ATag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      SaltSize := ASN1ReadInteger(TElASN1SimpleTag(ATag.GetField(0)));
      Index := 3;
    end
    else
    if ATag.TagId = SB_ASN1_A3 then
    begin
      { trailer }
      if (Index > 3) or (not ATag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      TrailerField := ASN1ReadInteger(TElASN1SimpleTag(ATag.GetField(0)));

      if TrailerField <> 1 then //only this type currently declared.
        raise EElAlgorithmIdentifierError.Create(SUnsupportedAlgorithmParameters);

      Index := 4;
    end
    else
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
  end;
end;

procedure TElRSAPSSAlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
var
  aTag : TElASN1ConstrainedTag;
  sTag : TElASN1SimpleTag;
begin
  if FMGF <> SB_CERT_MGF1 then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

  if (FHashAlgorithm = SB_ALGORITHM_DGST_SHA1) and (FSaltSize = 20) and
    (FMGFHashAlgorithm = SB_ALGORITHM_DGST_SHA1) and (FTrailerField = 1) then
  begin
    Tag.AddField(false);
    Tag.GetField(1).TagId := SB_ASN1_NULL;
    Exit;
  end;

  Tag.AddField(true);
  Tag.GetField(1).TagId := SB_ASN1_SEQUENCE;
  Tag := TElASN1ConstrainedTag(Tag.GetField(1));

  { hash algorithm }

  if FHashAlgorithm <> SB_ALGORITHM_DGST_SHA1 then
  begin
    aTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    aTag.TagId := SB_ASN1_A0;
    aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));

    aTag.TagId := SB_ASN1_SEQUENCE;

    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
    sTag.TagId := SB_ASN1_OBJECT;
    sTag.Content := GetOIDByHashAlgorithm(FHashAlgorithm);
    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
    sTag.TagId := SB_ASN1_NULL;
  end;

  { MGF }
  if (HashAlgorithm <> SB_ALGORITHM_DGST_SHA1) then
  begin
    aTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    aTag.TagId := SB_ASN1_A1;
    aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));
    aTag.TagId := SB_ASN1_SEQUENCE;

    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
    sTag.TagId := SB_ASN1_OBJECT;
    sTag.Content := SB_OID_MGF1;

    aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));
    aTag.TagId := SB_ASN1_SEQUENCE;

    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
    sTag.TagId := SB_ASN1_OBJECT;
    sTag.Content := GetOIDByHashAlgorithm(FHashAlgorithm);

    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
    sTag.TagId := SB_ASN1_NULL;
  end;

  { SaltSize }

  aTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  aTag.TagId := SB_ASN1_A2;

  sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
  sTag.TagId := SB_ASN1_INTEGER;
  ASN1WriteInteger(sTag, SaltSize);

  { TrailerField}

  if FTrailerField <> 1 then
  begin
    aTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    aTag.TagId := SB_ASN1_A3;

    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
    sTag.TagId := SB_ASN1_INTEGER;
    ASN1WriteInteger(sTag, TrailerField);
  end;
end;

function TElRSAPSSAlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_RSAPSS);
end;

function TElRSAPSSAlgorithmIdentifier.GetIsSignatureAlgorithm : boolean;
begin
  Result := true;
end;

function TElRSAPSSAlgorithmIdentifier.GetIsPublicKeyAlgorithm : boolean;
begin
  Result := true;
end;

function TElRSAPSSAlgorithmIdentifier.GetIsEncryptionAlgorithm : boolean;
begin
  Result := false;
end;

function TElRSAPSSAlgorithmIdentifier.GetSignatureHashAlgorithm : integer;
begin
  Result := HashAlgorithm;
end;

{ TElRSAOAEPAlgorithmIdentifier }

constructor TElRSAOAEPAlgorithmIdentifier.Create;
begin
  inherited;

  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FMGF := SB_CERT_MGF1;
  FMGFHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FStrLabel := '';
  FAlgorithmOID := SB_OID_RSAOAEP;
  FAlgorithm := SB_CERT_ALGORITHM_ID_RSAOAEP;
  FWriteDefaults := false;
end;

procedure TElRSAOAEPAlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;

  if Source is TElRSAAlgorithmIdentifier then
  begin
    FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
    FStrLabel := '';
    FMGF := SB_CERT_MGF1;
    FMGFHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  end
  else
  if (Source is TElRSAOAEPAlgorithmIdentifier) then
  begin
    FHashAlgorithm := TElRSAOAEPAlgorithmIdentifier(Source).FHashAlgorithm;
    FStrLabel := TElRSAOAEPAlgorithmIdentifier(Source).FStrLabel;
    FMGF := TElRSAOAEPAlgorithmIdentifier(Source).FMGF;
    FMGFHashAlgorithm := TElRSAOAEPAlgorithmIdentifier(Source).FMGFHashAlgorithm;
  end
  else
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer);
end;

procedure TElRSAOAEPAlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
var
  ATag, STag : TElASN1ConstrainedTag;
  Index, TagNum : integer;
begin
  { default parameters }
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FMGFHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FMGF := SB_CERT_MGF1;
  FStrLabel := '';

  if Tag.GetField(1).CheckType(SB_ASN1_NULL, false) then
    Exit; // default parameters should be used

  if (not Tag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

  STag := TElASN1ConstrainedTag(Tag.GetField(1));
  if STag.Count > 3 then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

  Index := 0;
  TagNum := 0;

  while (Index < 3) and (TagNum < STag.Count) do
  begin
    ATag := TElASN1ConstrainedTag(STag.GetField(TagNum));
    Inc(TagNum);

    if (not ATag.IsConstrained) or (ATag.Count <> 1) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    if (ATag.TagId = SB_ASN1_A0) then
    begin
      { hash algorithm }
      if (Index > 0) or (not ATag.GetField(0).IsConstrained) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      ATag := TElASN1ConstrainedTag(ATag.GetField(0));
      if (ATag.Count > 2) or (ATag.Count < 1) or (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      if (ATag.Count > 1) and (not ATag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      FHashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(ATag.GetField(0)).Content);

      Index := 1;
    end
    else
    if (ATag.TagId = SB_ASN1_A1) then
    begin
      { MGF }
      if (Index > 10) or (not ATag.GetField(0).IsConstrained) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      ATag := TElASN1ConstrainedTag(ATag.GetField(0));
      if (ATag.Count <> 2) or
        (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
        (not ATag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true))
      then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      if not CompareContent(TElASN1SimpleTag(ATag.GetField(0)).Content, SB_OID_MGF1)
      then
        raise EElAlgorithmIdentifierError.Create(SUnsupportedAlgorithmParameters);

      ATag := TElASN1ConstrainedTag(ATag.GetField(1));

      if (ATag.Count > 2) or (ATag.Count < 1) or (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      if (ATag.Count > 1) and (not ATag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      FMGFHashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(ATag.GetField(0)).Content);

      Index := 2;
    end
    else
    if ATag.TagId = SB_ASN1_A2 then
    begin
      { StrLabel }
      if (Index > 2) or (not ATag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      ATag := TElASN1ConstrainedTag(ATag.GetField(0));
      if (ATag.Count <> 2) or (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false))
      then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      if not CompareContent(TElASN1SimpleTag(ATag.GetField(0)).Content, SB_OID_OAEP_SRC_SPECIFIED)
      then
        raise EElAlgorithmIdentifierError.Create(SUnsupportedAlgorithmParameters);

      if not ATag.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false) then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      FStrLabel := StringOfBytes(TElASN1SimpleTag(ATag.GetField(1)).Content);

      Index := 3;
    end
    else
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
  end;
end;


procedure TElRSAOAEPAlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
var
  aTag : TElASN1ConstrainedTag;
  sTag : TElASN1SimpleTag;
begin
  if FMGF <> SB_CERT_MGF1 then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

  if (not FWriteDefaults) and (FHashAlgorithm = SB_ALGORITHM_DGST_SHA1) and (Length(FStrLabel) = 0) and
    (FMGFHashAlgorithm = SB_ALGORITHM_DGST_SHA1) then
  begin
    Tag.AddField(false);
    Tag.GetField(1).TagId := SB_ASN1_NULL;
    Exit;
  end;

  Tag.AddField(true);
  Tag.GetField(1).TagId := SB_ASN1_SEQUENCE;
  Tag := TElASN1ConstrainedTag(Tag.GetField(1));

  { hash algorithm }

  if FWriteDefaults or (FHashAlgorithm <> SB_ALGORITHM_DGST_SHA1) then
  begin
    aTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(True)));
    aTag.TagId := SB_ASN1_A0;
    aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));

    aTag.TagId := SB_ASN1_SEQUENCE;

    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
    sTag.TagId := SB_ASN1_OBJECT;
    sTag.Content := GetOIDByHashAlgorithm(FHashAlgorithm);
    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
    sTag.TagId := SB_ASN1_NULL;
  end;

  { MGF }

  if FWriteDefaults or (FMGFHashAlgorithm <> SB_ALGORITHM_DGST_SHA1) then
  begin
    aTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(True)));
    aTag.TagId := SB_ASN1_A1;
    aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));

    aTag.TagId := SB_ASN1_SEQUENCE;
    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
    sTag.TagId := SB_ASN1_OBJECT;
    sTag.Content := SB_OID_MGF1;
    
    aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(True)));
    aTag.TagId := SB_ASN1_SEQUENCE;
    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
    sTag.TagId := SB_ASN1_OBJECT;
    sTag.Content := GetOIDByHashAlgorithm(FMGFHashAlgorithm);
    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
    sTag.TagId := SB_ASN1_NULL;
  end;

  { label source }
  if StrLabel <> '' then
  begin
    aTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(True)));
    aTag.TagId := SB_ASN1_A2;
    aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));

    aTag.TagId := SB_ASN1_SEQUENCE;
    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
    sTag.TagId := SB_ASN1_OBJECT;
    sTag.Content := SB_OID_OAEP_SRC_SPECIFIED;
    sTag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
    sTag.TagId := SB_ASN1_OCTETSTRING;
    sTag.Content := BytesOfString(StrLabel);
  end;
end;

function TElRSAOAEPAlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_RSAOAEP);
end;

function TElRSAOAEPAlgorithmIdentifier.GetIsSignatureAlgorithm : boolean;
begin
  Result := false;
end;

function TElRSAOAEPAlgorithmIdentifier.GetIsPublicKeyAlgorithm : boolean;
begin
  Result := true;
end;

function TElRSAOAEPAlgorithmIdentifier.GetIsEncryptionAlgorithm : boolean;
begin
  Result := true;
end;

{ TElDSAAlgorithmIdentifier}

constructor TElDSAAlgorithmIdentifier.Create;
begin
  inherited;

  FAlgorithmOID := SB_OID_DSA;
  FAlgorithm := SB_CERT_ALGORITHM_ID_DSA;
  SetLength(FP, 0);
  SetLength(FQ, 0);
  SetLength(FG, 0);
end;

 destructor  TElDSAAlgorithmIdentifier.Destroy; 
begin
  ReleaseArray(FP);
  ReleaseArray(FQ);
  ReleaseArray(FG);
  inherited;
end;

procedure TElDSAAlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;

  if not (Source is TElDSAAlgorithmIdentifier) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer)
  else
  begin
    FP := CloneArray(TElDSAAlgorithmIdentifier(Source).FP);
    FQ := CloneArray(TElDSAAlgorithmIdentifier(Source).FQ);
    FG := CloneArray(TElDSAAlgorithmIdentifier(Source).FG);
  end;
end;

procedure TElDSAAlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
var
  cTag : TElASN1ConstrainedTag;
begin
  if (CompareContent(SB_OID_DSA_SHA1, FAlgorithmOID) or
    CompareContent(SB_OID_DSA_SHA1_ALT, FAlgorithmOID)) and
    (Tag.Count > 1) and (Tag.GetField(1).TagId <> SB_ASN1_NULL)
  then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

  if (Tag.Count = 2) and ((FAlgorithm = SB_CERT_ALGORITHM_ID_DSA)) then
  begin
    if Tag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true) then
    begin
      cTag := TElASN1ConstrainedTag(Tag.GetField(1));
      if (cTag.Count <> 3) or (not cTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) or
        (not cTag.GetField(1).CheckType(SB_ASN1_INTEGER, false)) or
        (not cTag.GetField(2).CheckType(SB_ASN1_INTEGER, false))
      then
        raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

      FP := ReadASN1TagData(TElASN1SimpleTag(cTag.GetField(0)));
      FQ := ReadASN1TagData(TElASN1SimpleTag(cTag.GetField(1)));
      FG := ReadASN1TagData(TElASN1SimpleTag(cTag.GetField(2)));
    end
    { specification doesn't allow NULL here, but there are such private keys in the real world }
    else if not Tag.GetField(1).CheckType(SB_ASN1_NULL, false) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
  end;
end;

procedure TElDSAAlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
var
  cTag : TElASN1ConstrainedTag;
begin
  if (FAlgorithm = SB_CERT_ALGORITHM_ID_DSA) and (Length(FP) > 0) and
    (Length(FQ) > 0) and (Length(FG) > 0)
  then
  begin
    Tag.AddField(true);
    cTag := TElASN1ConstrainedTag(Tag.GetField(1));
    cTag.TagId := SB_ASN1_SEQUENCE;
    cTag.AddField(false);
    cTag.GetField(0).TagId := SB_ASN1_INTEGER;
    cTag.AddField(false);
    cTag.GetField(1).TagId := SB_ASN1_INTEGER;
    cTag.AddField(false);
    cTag.GetField(2).TagId := SB_ASN1_INTEGER;
    WriteASN1TagData(TElASN1SimpleTag(cTag.GetField(0)), FP);
    WriteASN1TagData(TElASN1SimpleTag(cTag.GetField(1)), FQ);
    WriteASN1TagData(TElASN1SimpleTag(cTag.GetField(2)), FG);
  end;
end;

function TElDSAAlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_DSA) or CompareContent(OID, SB_OID_DSA_ALT)
    or CompareContent(OID, SB_OID_DSA_SHA1) or CompareContent(OID, SB_OID_DSA_SHA1_ALT);
end;

function TElDSAAlgorithmIdentifier.GetIsSignatureAlgorithm : boolean;
begin
  Result := (Algorithm = SB_CERT_ALGORITHM_ID_DSA_SHA1);
end;

function TElDSAAlgorithmIdentifier.GetIsPublicKeyAlgorithm : boolean;
begin
  Result := (Algorithm = SB_CERT_ALGORITHM_ID_DSA);
end;

function TElDSAAlgorithmIdentifier.GetIsEncryptionAlgorithm : boolean;
begin
  Result := false;
end;

function TElDSAAlgorithmIdentifier.GetSignatureHashAlgorithm : integer;
begin
  Result := SB_ALGORITHM_DGST_SHA1;
end;

procedure TElDSAAlgorithmIdentifier.SetP(const V : ByteArray);
begin
  FP := CloneArray(V);
end;

procedure TElDSAAlgorithmIdentifier.SetQ(const V : ByteArray);
begin
  FQ := CloneArray(V);
end;

procedure TElDSAAlgorithmIdentifier.SetG(const V : ByteArray);
begin
  FG := CloneArray(V);
end;

{ TElDHAlgorithmIdentifier}

constructor TElDHAlgorithmIdentifier.Create;
begin
  inherited;

  FAlgorithmOID := SB_OID_DH;
  FAlgorithm := SB_CERT_ALGORITHM_DH_PUBLIC;
  SetLength(FP, 0);
  SetLength(FQ, 0);
  SetLength(FG, 0);
end;

 destructor  TElDHAlgorithmIdentifier.Destroy;
begin
  ReleaseArray(FP);
  ReleaseArray(FQ);
  ReleaseArray(FG);
  inherited;
end;

procedure TElDHAlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;

  if not (Source is TElDHAlgorithmIdentifier) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer)
  else
  begin
    FP := CloneArray(TElDHAlgorithmIdentifier(Source).FP);
    FQ := CloneArray(TElDHAlgorithmIdentifier(Source).FQ);
    FG := CloneArray(TElDHAlgorithmIdentifier(Source).FG);
  end;
end;

procedure TElDHAlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
var
  cTag : TElASN1ConstrainedTag;
begin
  if (Tag.Count = 2) then
  begin
    if (not Tag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    cTag := TElASN1ConstrainedTag(Tag.GetField(1));
    if (cTag.Count < 3) or (not cTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) or
      (not cTag.GetField(1).CheckType(SB_ASN1_INTEGER, false)) or
      (not cTag.GetField(2).CheckType(SB_ASN1_INTEGER, false))
    then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    FP := ReadASN1TagData(TElASN1SimpleTag(cTag.GetField(0)));
    FG := ReadASN1TagData(TElASN1SimpleTag(cTag.GetField(1)));
    FQ := ReadASN1TagData(TElASN1SimpleTag(cTag.GetField(2)));
  end
  else
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
end;

procedure TElDHAlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
var
  cTag : TElASN1ConstrainedTag;
begin
  Tag.AddField(true);
  cTag := TElASN1ConstrainedTag(Tag.GetField(1));
  cTag.TagId := SB_ASN1_SEQUENCE;
  cTag.AddField(false);
  cTag.GetField(0).TagId := SB_ASN1_INTEGER;
  cTag.AddField(false);
  cTag.GetField(1).TagId := SB_ASN1_INTEGER;
  cTag.AddField(false);
  cTag.GetField(2).TagId := SB_ASN1_INTEGER;
  WriteASN1TagData(TElASN1SimpleTag(cTag.GetField(0)), FP);
  WriteASN1TagData(TElASN1SimpleTag(cTag.GetField(1)), FG);
  WriteASN1TagData(TElASN1SimpleTag(cTag.GetField(2)), FQ);
end;

function TElDHAlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_DH);
end;

function TElDHAlgorithmIdentifier.GetIsSignatureAlgorithm : boolean;
begin
  Result := false;
end;

function TElDHAlgorithmIdentifier.GetIsPublicKeyAlgorithm : boolean;
begin
  Result := true;
end;

function TElDHAlgorithmIdentifier.GetIsEncryptionAlgorithm : boolean;
begin
  Result := true;
end;

procedure TElDHAlgorithmIdentifier.SetP(const V : ByteArray);
begin
  FP := CloneArray(V);
end;

procedure TElDHAlgorithmIdentifier.SetQ(const V : ByteArray);
begin
  FQ := CloneArray(V);
end;

procedure TElDHAlgorithmIdentifier.SetG(const V : ByteArray);
begin
  FG := CloneArray(V);
end;


{$ifdef SB_HAS_GOST}
{ TElGOST3411AlgorithmIdentifier }

procedure TElGOST3411AlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
begin
  inherited; // NULL or emtpy parameters field
end;

procedure TElGOST3411AlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
begin
  Tag.AddField(false);
  Tag.GetField(1).TagId := SB_ASN1_NULL;
end;

function TElGOST3411AlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_GOST_R3411_1994);
end;

procedure TElGOST3411AlgorithmIdentifier.SetAlgorithmOID(const Value : ByteArray);
var
  Alg : integer;
begin
  if not CheckAlgorithmOID(Value) then
    Exit;

  Alg := GetHashAlgorithmByOID(Value);
  FAlgorithmOID := CloneArray(Value);
  FAlgorithm := Alg;
end;

function TElGOST3411AlgorithmIdentifier.GetIsHashAlgorithm : boolean;
begin
  Result := true;
end;

constructor TElGOST3411AlgorithmIdentifier.Create;
begin
  inherited Create;

  SetAlgorithmOID(SB_OID_GOST_R3411_1994);
end;

procedure TElGOST3411AlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;

  if not (Source is TElGOST3411AlgorithmIdentifier) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer)
end;

{ TElGOST3410ALgorithmIdentifier }

procedure TElGOST3410AlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
var
  cTag : TElASN1ConstrainedTag;
begin
  if (Tag.Count < 2) or (Tag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
    Exit;

  if Tag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true) then
  begin
    cTag := TElASN1ConstrainedTag(Tag.GetField(1));
    if (cTag.Count < 2) or (cTag.Count > 3) or
      (not cTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
      (not cTag.GetField(1).CheckType(SB_ASN1_OBJECT, false))
    then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    if (cTag.Count = 3) and (not cTag.GetField(2).CheckType(SB_ASN1_OBJECT, false)) then
      raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);

    FPublicKeyParamSet := TElASN1SimpleTag(cTag.GetField(0)).Content;
    FDigestParamSet := TElASN1SimpleTag(cTag.GetField(1)).Content;

    if cTag.Count = 3 then
      FEncryptionParamSet := TElASN1SimpleTag(cTag.GetField(2)).Content
    else
      FEncryptionParamSet := SB_OID_GOST_28147_1989_PARAM_CP_A;
  end
  else
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
end;

procedure TElGOST3410AlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
var
  cTag : TElASN1ConstrainedTag;
begin
  if (Length(FPublicKeyParamSet) > 0) and (Length(FDigestParamSet) > 0) then
  begin
    Tag.AddField(true);
    cTag := TElASN1ConstrainedTag(Tag.GetField(1));
    cTag.TagId := SB_ASN1_SEQUENCE;
    cTag.AddField(false);
    cTag.GetField(0).TagId := SB_ASN1_OBJECT;
    TElASN1SimpleTag(cTag.GetField(0)).Content := CloneArray(FPublicKeyParamSet);
    cTag.AddField(false);
    cTag.GetField(1).TagId := SB_ASN1_OBJECT;
    TElASN1SimpleTag(cTag.GetField(1)).Content := CloneArray(FDigestParamSet);

    if Length(FEncryptionParamSet) > 0 then
    begin
      cTag.AddField(false);
      cTag.GetField(2).TagId := SB_ASN1_OBJECT;
      TElASN1SimpleTag(cTag.GetField(2)).Content := CloneArray(FEncryptionParamSet);
    end;
  end;
end;

function TElGOST3410AlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_GOST_R3410_1994) or CompareContent(OID, SB_OID_GOST_R3410_2001);
end;

procedure TElGOST3410AlgorithmIdentifier.SetAlgorithmOID(const Value : ByteArray);
begin
  inherited;
end;

function TElGOST3410AlgorithmIdentifier.GetIsPublicKeyAlgorithm : boolean;
begin
  Result := true;
end;

constructor TElGOST3410AlgorithmIdentifier.Create;
begin
  inherited;

  FAlgorithmOID := SB_OID_GOST_R3410_1994;
  FAlgorithm := SB_ALGORITHM_PK_GOST_R3410_1994;
  FPublicKeyParamSet := SB_OID_GOST_R3410_1994_PARAM_CP_A;
  FDigestParamSet := SB_OID_GOST_R3411_1994_PARAM_CP;
  FEncryptionParamSet := SB_OID_GOST_28147_1989_PARAM_CP_A;
end;

 destructor  TElGOST3410AlgorithmIdentifier.Destroy; 
begin
  inherited;
end;

procedure TElGOST3410AlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;

  if not (Source is TElGOST3410AlgorithmIdentifier) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmIdentifer)
  else
  begin
    FPublicKeyParamSet := CloneArray(TElGOST3410AlgorithmIdentifier(Source).PublicKeyParamSet);
    FDigestParamSet := CloneArray(TElGOST3410AlgorithmIdentifier(Source).DigestParamSet);
    FEncryptionParamSet := CloneArray(TElGOST3410AlgorithmIdentifier(Source).EncryptionParamSet);
  end;
end;

procedure TElGOST3410AlgorithmIdentifier.SetPublicKeyParamSet(const V : ByteArray);
begin
  FPublicKeyParamSet := CloneArray(V);
end;

procedure TElGOST3410AlgorithmIdentifier.SetDigestParamSet(const V : ByteArray);
begin
  FDigestParamSet := CloneArray(V);
end;

procedure TElGOST3410AlgorithmIdentifier.SetEncryptionParamSet(const V : ByteArray);
begin
  FEncryptionParamSet := CloneArray(V);
end;

{ TElGOST3410WithGOST3411AlgorithmIdentifier}

constructor TElGOST3411WithGOST3410AlgorithmIdentifier.Create;
begin
  inherited;

  FAlgorithmOID := SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994;
  FAlgorithm := SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994;
end;

procedure TElGOST3411WithGOST3410AlgorithmIdentifier.Assign(Source: TElAlgorithmIdentifier);
begin
  inherited;
end;

procedure TElGOST3411WithGOST3410AlgorithmIdentifier.LoadParameters(Tag : TElASN1ConstrainedTag);
begin
  if not ((Tag.Count = 1) or ((Tag.Count = 2) and (Tag.GetField(1).CheckType(SB_ASN1_NULL, false)))) then
    raise EElAlgorithmIdentifierError.Create(SInvalidAlgorithmParameters);
end;

procedure TElGOST3411WithGOST3410AlgorithmIdentifier.SaveParameters(Tag : TElASN1ConstrainedTag);
begin
end;

function TElGOST3411WithGOST3410AlgorithmIdentifier.CheckAlgorithmOID(const OID : ByteArray) : boolean;
begin
  Result := CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994) or
    CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001);
end;

function TElGOST3411WithGOST3410AlgorithmIdentifier.GetIsSignatureAlgorithm : boolean;
begin
  Result := true;
end;

function TElGOST3411WithGOST3410AlgorithmIdentifier.GetSignatureHashAlgorithm : integer;
begin
  Result := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;
 {$endif}


end.
