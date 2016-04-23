
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBPEM;

interface

uses
  SysUtils,
  Classes,
  {$ifdef WIN32}
  Windows,
   {$else}
  //{$ifndef FPC}Libc,{$endif}
   {$endif}
  SBTypes,
  SBUtils,
  SBConstants,
  SBEncoding,
  SBSymmetricCrypto,
  SBHashFunction
  ;


const
  PEM_DECODE_RESULT_OK                  = Integer(0);
  PEM_DECODE_RESULT_INVALID_FORMAT      = Integer($1D01);
  PEM_DECODE_RESULT_INVALID_PASSPHRASE  = Integer($1D02);
  PEM_DECODE_RESULT_NOT_ENOUGH_SPACE    = Integer($1D03);
  PEM_DECODE_RESULT_UNKNOWN_CIPHER      = Integer($1D04);

type

  TElPEMProcessor = class(TSBComponentBase)
  protected
    FHeader : string;
    FPassphrase: string;
    FEncryptionAlgorithm: integer;
    FEncryptionMode :  TSBSymmetricCryptoMode ;
  public
    constructor Create(AOwner : TSBComponentBase);{$ifndef SB_NO_COMPONENT} override;  {$endif}
        
    {$ifndef SB_PGPSFX_STUB} 
    function PEMEncode(const InBuffer : ByteArray;  var  OutBuffer : ByteArray; Encrypt : boolean) : boolean;  overload; 
     {$endif}
    function PEMDecode(const InBuffer : ByteArray;  var  OutBuffer : ByteArray) : integer;   overload; 

    {$ifndef SB_PGPSFX_STUB}
    function PEMEncode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer; Encrypt : boolean) : boolean; overload;
     {$endif}
    function PEMDecode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer; overload;
  published
    property Header : string read FHeader write FHeader;
    property Passphrase: string read FPassphrase write FPassphrase;
    property EncryptionAlgorithm : integer read FEncryptionAlgorithm write FEncryptionAlgorithm;
    property EncryptionMode :  TSBSymmetricCryptoMode  read FEncryptionMode write FEncryptionMode;
  end;

{$ifndef SB_PGPSFX_STUB}
function Encode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer; const Header : string; Encrypt : boolean;
  const PassPhrase : string) : boolean;
function EncodeEx(InBuffer : pointer; InSize : integer; OutBuffer : pointer; var OutSize : integer;
  const Header : string; EncryptionAlgorithm : integer; const PassPhrase : string) : boolean; overload;
function EncodeEx(InBuffer : pointer; InSize : integer; OutBuffer : pointer; var OutSize : integer;
  const Header : string; EncryptionAlgorithm : integer; EncryptionMode :  TSBSymmetricCryptoMode ; const PassPhrase : string) : boolean; overload;
 {$endif}
function Decode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  const PassPhrase : string; var OutSize : integer; var Header : string) : integer;

function IsBase64UnicodeSequence(Buffer : pointer; Size : integer) : boolean;
function IsBase64Sequence(Buffer : pointer; Size : integer) : boolean;
function IsPEMSequence(Buffer : pointer; Size : integer) : boolean;


type
  EElPEMError =  class(ESecureBlackboxError);

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

  PEM_BEGIN_CERTIFICATE_LINE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = '-----BEGIN CERTIFICATE-----' {$endif};  
  PEM_END_CERTIFICATE_LINE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = '-----END CERTIFICATE-----' {$endif};  


procedure RaisePEMError(ErrorCode : integer); 

implementation

uses
  SBStrUtils,
  SBRandom
  ;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
  PEM_BEGIN_CERTIFICATE_LINE_STR = '-----BEGIN CERTIFICATE-----';
  PEM_END_CERTIFICATE_LINE_STR = '-----END CERTIFICATE-----';
 {$endif}

resourcestring

  sInvalidPEMFormat     = 'Invalid file format (possibly not a PEM?)';
  sIncorrectPassphrase  = 'Incorrect password';
  sNotEnoughBufferSpace = 'Not enough buffer space';
  sUnknownCipher        = 'Unsupported data encryption method';

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

  PEM_BUFFER_DEK_INFO : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = 'DEK-Info:' {$endif}; 

procedure RaisePEMError(ErrorCode : integer);
begin
  case ErrorCode of
    PEM_DECODE_RESULT_INVALID_FORMAT     : raise EElPEMError.Create(sInvalidPEMFormat, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    PEM_DECODE_RESULT_INVALID_PASSPHRASE : raise EElPEMError.Create(sIncorrectPassphrase, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    PEM_DECODE_RESULT_NOT_ENOUGH_SPACE   : raise EElPEMError.Create(sNotEnoughBufferSpace, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    PEM_DECODE_RESULT_UNKNOWN_CIPHER     : raise EElPEMError.Create(sUnknownCipher, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    else
      exit;
  end;
end;

function DeriveKey(const Passphrase, Salt : ByteArray; Needed : integer) : ByteArray;
var
  HashFunc :  TElHashFunction ;
  Res, Hash : ByteArray;
  Index, HashIndex : integer;
begin
  HashFunc :=  TElHashFunction .Create(SB_ALGORITHM_DGST_MD5);
  SetLength(Res, Needed);
  SetLength(Hash, 0);
  Index := 0;


  while (Index < Needed) do
  begin
    if Length(Hash) > 0 then
      HashFunc.Update( @Hash[0] , Length(Hash));
    HashFunc.Update( @Passphrase[0] , Length(Passphrase));
    if Length(Salt) > 0 then
      HashFunc.Update( @Salt[0] , 8); // OpenSSL always uses 8 bytes of salt here.
    Hash := HashFunc.Finish;
    HashFunc.Reset;
    HashIndex := 0;

    while (Index < Needed) and (HashIndex < Length(Hash)) do
    begin
      Res[Index] := Hash[HashIndex];
      Inc(Index);
      Inc(HashIndex);
    end;
  end;

  Result := Res;
  FreeAndNil(HashFunc);

end;

{$ifndef SB_PGPSFX_STUB}


function EncodeEx(InBuffer : pointer; InSize : integer; OutBuffer : pointer; var OutSize : integer;
  const Header : string; EncryptionAlgorithm : integer; const PassPhrase : string) : boolean;
begin
  Result := EncodeEx(InBuffer, InSize, OutBuffer, OutSize, Header, EncryptionAlgorithm,  cmCBC , PassPhrase);
end;


function EncodeEx(InBuffer : pointer; InSize : integer; OutBuffer : pointer; var OutSize : integer;
  const Header : string; EncryptionAlgorithm : integer; EncryptionMode:  TSBSymmetricCryptoMode ; const PassPhrase : string) : boolean;
var
  PEMBeginLine, PEMEndLine, PEMHeaders : ByteArray;
  Crypto :  TElSymmetricCrypto ;
  KeyMaterial :  TElSymmetricKeyMaterial ;
  Factory :  TElSymmetricCryptoFactory ;
  InBuf, OutBuf, Key, IV : ByteArray;
  I, EstSize, Size : integer;
  DEKInfo : string;
  Tmp, Tmp1, Tmp2 : ByteArray;
begin
  Result := false;
  Key := EmptyArray; // to make compiler happy

  

  if EncryptionAlgorithm <> SB_ALGORITHM_CNT_IDENTITY then
  begin
    if EncryptionMode =  cmCBC 
    then
    begin
      {$ifndef SB_NO_DES}
      if EncryptionAlgorithm = SB_ALGORITHM_CNT_DES then
        DEKInfo := 'DEK-Info: DES-CBC,'
      else if EncryptionAlgorithm = SB_ALGORITHM_CNT_3DES then
        DEKInfo := 'DEK-Info: DES-EDE3-CBC,'
      else
       {$endif}
      if EncryptionAlgorithm = SB_ALGORITHM_CNT_AES128 then
        DEKInfo := 'DEK-Info: AES-128-CBC,'
      else if EncryptionAlgorithm = SB_ALGORITHM_CNT_AES192 then
        DEKInfo := 'DEK-Info: AES-192-CBC,'
      else if EncryptionAlgorithm = SB_ALGORITHM_CNT_AES256 then
        DEKInfo := 'DEK-Info: AES-256-CBC,'
      else
      begin
        OutSize := 0;
        Exit;
      end;
    end
    else if EncryptionMode =  cmCFB8  then
    begin
      if EncryptionAlgorithm = SB_ALGORITHM_CNT_3DES then
        DEKInfo := 'DEK-Info: DES-EDE3-CFB,'
    end
    else
    begin
      OutSize := 0;
      Exit;
    end;

    Factory :=  TElSymmetricCryptoFactory.Create ;
    try
      try
        Crypto := Factory.CreateInstance(EncryptionAlgorithm, EncryptionMode);
      except
        OutSize := 0;
        Exit;
      end;
    finally
      FreeAndNil(Factory);
    end;

    SetLength(IV, Crypto.BlockSize);
    SBRndGenerate( @IV[0] , Length(IV));
    Key := DeriveKey(BytesOfString(Passphrase), IV, Crypto.KeySize);
    KeyMaterial :=  TElSymmetricKeyMaterial .Create();
    KeyMaterial.Key := Key;
    KeyMaterial.IV := IV;
    Crypto.KeyMaterial := KeyMaterial;
    if EncryptionMode =  cmCBC  then
      Crypto.Padding :=  cpPKCS5 
    else
      Crypto.Padding :=  cpNone ;

    try
      Size := 0;

      Crypto.Encrypt(InBuffer, InSize, nil, Size);
      SetLength(InBuf, Size);
      Crypto.Encrypt(InBuffer, InSize, @InBuf[0], Size);

      SetLength(InBuf, Size);
    finally
      FreeAndNil(Crypto);
      FreeAndNil(KeyMaterial);
    end;

    Tmp1 := BytesOfString('Proc-Type: 4,ENCRYPTED'#$0D#$0A);
    Tmp2 := BytesOfString(DEKInfo);
    PEMHeaders := SBConcatArrays(Tmp1, Tmp2);
    ReleaseArray(Tmp1);
    ReleaseArray(Tmp2);

    for I := 0 to Length(IV) - 1 do
    begin
      Tmp1 := PEMHeaders;
      Tmp2 := BytesOfString( IntToHex(IV[I], 2) );
      PEMHeaders := SBConcatArrays(Tmp1, Tmp2);
      ReleaseArray(Tmp1);
      ReleaseArray(Tmp2);
    end;
    Tmp := PEMHeaders;
    PEMHeaders := SBConcatArrays(PEMHeaders, CRLFCRLFByteArray);
    ReleaseArray(Tmp);
  end
  else
  begin
    SetLength(InBuf, InSize);
    SBMove(InBuffer^, InBuf[0], Length(InBuf));
    
    SetLength(PEMHeaders, 0);
  end;

  Size := 0;
  Base64Encode(@InBuf[0], Length(InBuf), nil, Size, true);
  SetLength(OutBuf, Size);
  if not Base64Encode(@InBuf[0], Length(InBuf), @OutBuf[0], Size, true) then
    Exit;
  SetLength(OutBuf, Size);

  Tmp := BytesOfString(Header);
  PEMBeginLine := SBConcatMultipleArrays([
        BeginLineByteArray,
        Tmp,
        FiveDashesByteArray,
        CRLFByteArray,
        PEMHeaders]);
  ReleaseArray(Tmp);

  Tmp := BytesOfString(Header);
  PEMEndLine := SBConcatMultipleArrays([
        CRByteArray,
        LFEndLineByteArray,
        Tmp,
        FiveDashesByteArray,
        CRLFByteArray]);
  ReleaseArray(Tmp);

  { Checking whether we have enough space in buffer }
  EstSize := Length(PEMBeginLine) + Length(PEMEndLine) + Size;
  if (OutSize < EstSize)  then
  begin
    OutSize := EstSize;
    Exit;
  end;
  SBMove(PEMBeginLine[0], PByteArray(OutBuffer)[0], Length(PEMBeginLine));
  SBMove(OutBuf[0], PByteArray(OutBuffer)[Length(PEMBeginLine)], Length(OutBuf));
  SBMove(PEMEndLine[0], PByteArray(OutBuffer)[Length(PEMBeginLine) + Length(OutBuf)],
    Length(PEMEndLine));
  OutSize := EstSize;
  Result := true;

end;

function Encode(InBuffer : pointer; InSize : integer; OutBuffer : pointer; var OutSize : integer;
  const Header : string; Encrypt : boolean; const PassPhrase : string) : boolean;
var
  Alg : integer;
begin
  if Encrypt then
    Alg := SB_ALGORITHM_CNT_3DES
  else
    Alg := SB_ALGORITHM_CNT_IDENTITY;

  Result := EncodeEx(InBuffer, InSize, OutBuffer, OutSize, Header, Alg, PassPhrase);
end;

 {$endif SB_PGPSFX_STUB}

function HexStringToBuffer(const HexStr : string) : ByteArray;
  function HexBytesToSym(B1, B2 : char) : byte;
  var
    P1, P2 : byte;
  begin
    if (B1 >= 'A') and (B1 <= 'F') then
      P1 := Ord(B1) - Ord('A') + 10
    else if (B1 >= '0') and (B1 <= '9') then
      P1 := Ord(B1) - Ord('0')
    else
      P1 := 0;
    if (B2 >= 'A') and (B2 <= 'F') then
      P2 := Ord(B2) - Ord('A') + 10
    else if (B2 >= '0') and (B2 <= '9') then
      P2 := Ord(B2) - Ord('0')
    else
      P2 := 0;
    Result := (P1 shl 4) or P2;
  end;
var
  I : integer;
begin
  if Length(HexStr) mod 2 <> 0 then
    SetLength(Result, 0)
  else
  begin
    SetLength(Result, Length(HexStr) shr 1);

    // TODO NEXTGEN: verify correctness of this optimization
    I := StringStartOffset;
    while I <= Length(Result) - StringStartInvOffset do
    begin
      Result[I - StringStartOffset + 0] :=
        byte(HexBytesToSym(HexStr[StringStartOffset + (I - StringStartOffset) shl 1], HexStr[StringStartOffset + (I - StringStartOffset) shl 1 + 1]));
      Inc(I);
    end;
  end;
end;

function HexBufferToBuffer(const HexBuf : ByteArray) : ByteArray;

  function HexBytesToSym(B1, B2 : byte) : byte;
  var
    P1, P2 : byte;
  begin
    if (B1 >= Ord('A')) and (B1 <= Ord('F')) then
      P1 := Ord(B1) - Ord('A') + 10
    else if (B1 >= Ord('0')) and (B1 <= Ord('9')) then
      P1 := Ord(B1) - Ord('0')
    else
      P1 := 0;
    if (B2 >= Ord('A')) and (B2 <= Ord('F')) then
      P2 := Ord(B2) - Ord('A') + 10
    else
    if (B2 >= Ord('0')) and (B2 <= Ord('9')) then
      P2 := Ord(B2) - Ord('0')
    else
      P2 := 0;
    Result := (P1 shl 4) or P2;
  end;
var
  I : integer;
begin
  if Length(HexBuf) mod 2 <> 0 then
    Result := EmptyArray
  else
  begin
    SetLength(Result, Length(HexBuf) shr 1);

    // TODO NEXTGEN: verify correctness of this optimization
    I := 0;
    while I <= Length(Result) - 1 do
    begin
      Result[I] := byte(
          HexBytesToSym(
            Ord(HexBuf[0 + (I - 0) shl 1]),
            Ord(HexBuf[0 + (I - 0) shl 1 + 1]))
          );
      Inc(I);
    end;
  end;
end;


function Decode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  const PassPhrase : string; var OutSize : integer; var Header : string) : integer;
var
  S1, S2 : ByteArray;
  S, Headers, Tmp : ByteArray;
  I, HeaderEnd, Res, Cipher, I1, I2, I3 : integer;
  IVSize : integer;
  Crypto :  TElSymmetricCrypto ;
  Factory :  TElSymmetricCryptoFactory ;
  KeyMaterial :  TElSymmetricKeyMaterial ;
  Sz : integer;
  EolLen : integer;
  BinBuf : ByteArray;
  CipherMode :  TSBSymmetricCryptoMode ;
  LTempS : ByteArray;

begin

  try

  Result := PEM_DECODE_RESULT_OK;
  SetLength(S, InSize);
  SBMove(InBuffer^, S[0], InSize);

  if SBPos(BeginLineByteArray, S) < 0 then
  begin
    Result := PEM_DECODE_RESULT_INVALID_FORMAT;
    Exit;
  end;

  I1 := SBPos(CRCRLFByteArray, S);
  I2 := SBPos(CRLFByteArray, S);
  I3 := SBPos(LFByteArray, S);

  {$ifdef SB_PASCAL_STRINGS}
  if I1 <= 0 then I1 := $7FFFFFFF;
  if I2 <= 0 then I2 := $7FFFFFFF;
  if I3 <= 0 then I3 := $7FFFFFFF;
  I := Min(Min(I1, I2), I3);
  if I = I1 then
    EolLen := 3
  else if I = I2 then
    EolLen := 2
  else
    EolLen := 1;
   {$else}
  if I1 < 0 then I1 := $7FFFFFFF;
  if I2 < 0 then I2 := $7FFFFFFF;
  if I3 < 0 then I3 := $7FFFFFFF;
  I := Min(Min(I1, I2), I3);
  if I = I1 then
    EolLen := 3
  else if I = I2 then
    EolLen := 2
  else
    EolLen := 1;
   {$endif}      

  if I = $7FFFFFFF then
  begin
    Result := PEM_DECODE_RESULT_INVALID_FORMAT;
    OutSize := 0;
    Exit;
  end;
  Header := StringOfBytes(SBCopy(S, ConstLength(BeginLineByteArray), I - ConstLength(FiveDashesByteArray) - ConstLength(BeginLineByteArray)));
  S := SBCopy(S, I + EolLen, Length(S));

  if SBPos(BytesOfString('Proc-Type'), S) = 0 then
  begin
    HeaderEnd := SBPos(CRCRLFCRCRLFByteArray, S);
    if HeaderEnd < 0 then
    begin
      HeaderEnd := SBPos(LFLFByteArray, S);
      if HeaderEnd < 0 then
        HeaderEnd := SBPos(CRLFCRLFByteArray, S);
    end;

    Headers := Copy(S, 0, HeaderEnd);

    while SBPos(PEM_BUFFER_DEK_INFO, Headers) > 0 do
    begin
      I := SBPos(LFByteArray, Headers);
      Tmp := Headers;
      Headers := Copy(Headers, I + 1, Length(Headers));
      ReleaseArray(Tmp);
    end;

    if SBPos(PEM_BUFFER_DEK_INFO, Headers) = 0 then
    begin
      I := SBPos(LFByteArray, Headers);

      if I >= 0 then
      begin
        Tmp := Headers;
        Headers := Copy(Headers, 0, I - 0);
        ReleaseArray(Tmp);
      end;

      I := SBPos(SpaceByteArray, Headers);
      Tmp := Headers;
      Headers := Copy(Headers, I + 1, Length(Headers));
      ReleaseArray(Tmp);

      I := SBPos(CommaByteArray, Headers);
      Tmp := Copy(Headers, 0, I - 0);

      CipherMode :=  cmCBC ;
      {$ifndef SB_NO_DES}
      if CompareContent(BytesOfString('DES-CBC'), Tmp) then
        Cipher := SB_ALGORITHM_CNT_DES
      else
      if CompareContent(BytesOfString('DES-EDE3-CBC'), Tmp) then
        Cipher := SB_ALGORITHM_CNT_3DES
      else
      if CompareContent(BytesOfString('DES-EDE3-CFB'), Tmp) then
      begin
        Cipher := SB_ALGORITHM_CNT_3DES;
        CipherMode := cmCFB8;
      end
      else
       {$endif}
      if CompareContent(BytesOfString('AES-128-CBC'), Tmp) then
        Cipher := SB_ALGORITHM_CNT_AES128
      else
      if CompareContent(BytesOfString('AES-192-CBC'), Tmp) then
        Cipher := SB_ALGORITHM_CNT_AES192
      else
      if CompareContent(BytesOfString('AES-256-CBC'), Tmp) then
        Cipher := SB_ALGORITHM_CNT_AES256
      else
      begin
        Result := PEM_DECODE_RESULT_UNKNOWN_CIPHER;
        Exit;
      end;

      Tmp := SBCopy(Headers, I + 1, Length(Headers));
      S1 := HexBufferToBuffer(Tmp);
      ReleaseArray(Tmp);

      SetLength(BinBuf, OutSize);      
      I := SBPos(LFEndLineByteArray, S);
      if I >= 0 then
      begin
        SetLength(LTempS, I - HeaderEnd - 2);
        SBMove(S, HeaderEnd + 2, LTempS, 0, I - HeaderEnd - 2);
      end;
      Res := Base64Decode(@LTempS[0], Length(LTempS), BinBuf, OutSize);

      if Res = 0 then
      begin
        Sz := OutSize;

        Factory :=  TElSymmetricCryptoFactory.Create ;
        try
          try
            Crypto := Factory.CreateInstance(Cipher, CipherMode);
          except
            Result := PEM_DECODE_RESULT_UNKNOWN_CIPHER;
            Exit;
          end;
        finally
          FreeAndNil(Factory);
        end;

        KeyMaterial :=  TElSymmetricKeyMaterial .Create();

        try
          S2 := DeriveKey(BytesOfString(Passphrase), S1, Crypto.KeySize);
          IVSize := Crypto.BlockSize;

          if Length(S1) <> IVSize then
          begin
            Result := PEM_DECODE_RESULT_INVALID_FORMAT;
            Exit;
          end;

          KeyMaterial.Key := S2;
          KeyMaterial.IV := S1;
          Crypto.KeyMaterial := KeyMaterial;
          Crypto.Padding :=  cpNone ;

          Crypto.Decrypt(@BinBuf[0], OutSize, OutBuffer, Sz);
        finally
          FreeAndNil(Crypto);
          FreeAndNil(KeyMaterial);
        end;

        if CipherMode =  cmCBC  then
        begin
        if PByteArray(OutBuffer)[Sz - 1] > IVSize then
        begin
          Result := PEM_DECODE_RESULT_INVALID_PASSPHRASE;
          Exit;
        end;
        OutSize := Sz - PByteArray(OutBuffer)[Sz - 1];
        end
        else
          OutSize := Sz;
          
        if OutSize < 0 then
        begin
          Result := PEM_DECODE_RESULT_INVALID_PASSPHRASE;
          Exit;
        end;
        Result := PEM_DECODE_RESULT_OK;
      end
      else
      if Res = BASE64_DECODE_NOT_ENOUGH_SPACE then
      begin
        Result := PEM_DECODE_RESULT_NOT_ENOUGH_SPACE;
        Exit;
      end
      else
      if Res = BASE64_DECODE_INVALID_CHARACTER then
      begin
        Result := PEM_DECODE_RESULT_INVALID_FORMAT;
        Exit;
      end;
    end
    else
    begin
      Result := PEM_DECODE_RESULT_INVALID_FORMAT;
      Exit;
    end;
  end
  else
  begin
    I := SBPos(LFEndLineByteArray, S);
    Result := Base64Decode(@S[0], I - 0, OutBuffer, OutSize, true);

    case Result of
      BASE64_DECODE_OK:
        Result := PEM_DECODE_RESULT_OK;
      BASE64_DECODE_NOT_ENOUGH_SPACE:
        Result := PEM_DECODE_RESULT_NOT_ENOUGH_SPACE
    else
      Result := PEM_DECODE_RESULT_INVALID_FORMAT;
    end;
  end;

  finally
    ReleaseArray(S1);
    ReleaseArray(S2);
    ReleaseArray(S);
    ReleaseArray(Headers);
    ReleaseArray(Tmp);
    ReleaseArray(BinBuf);
    ReleaseArray(LTempS);
  end;
end;

constructor TElPEMProcessor.Create(AOwner : TSBComponentBase);
begin
  inherited Create{$ifndef SB_NO_COMPONENT} (AOwner)  {$endif};

  FEncryptionAlgorithm := SB_ALGORITHM_CNT_3DES;
  FEncryptionMode :=  cmCBC ;
end;

{$ifndef SB_PGPSFX_STUB}
function TElPEMProcessor.PEMEncode(const InBuffer : ByteArray;  var  OutBuffer : ByteArray; Encrypt : boolean) : boolean;
var
  Alg, OutSize : integer;
begin
  if Encrypt then
    Alg := FEncryptionAlgorithm
  else
    Alg := SB_ALGORITHM_CNT_IDENTITY;

  OutSize := 0;
  EncodeEx(InBuffer,  Length(InBuffer),   nil,  OutSize, FHeader, Alg, FEncryptionMode, FPassphrase);
  SetLength(OutBuffer, OutSize);
  result := EncodeEx(InBuffer,  Length(InBuffer),  OutBuffer, OutSize, FHeader, Alg, FEncryptionMode, FPassphrase);
  if result then
  begin
    if (Length(OutBuffer) <> OutSize) then
     SetLength(OutBuffer, OutSize);
  end
  else
    SetLength(OutBuffer, 0);
end;
 {$endif}

{$ifndef SB_PGPSFX_STUB}
function TElPEMProcessor.PEMEncode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer; Encrypt : boolean) : boolean;
begin
  result := Encode(InBuffer, InSize, OutBuffer, OutSize, FHeader, Encrypt, FPassphrase);
end;
 {$endif}

function TElPEMProcessor.PEMDecode(const InBuffer : ByteArray;  var  OutBuffer : ByteArray) : integer;
var OutSize : integer;
begin
  OutSize := 0;
  result := Decode(InBuffer,  Length(InBuffer),    nil,  FPassphrase, OutSize, FHeader);
  if result = PEM_DECODE_RESULT_NOT_ENOUGH_SPACE then
  begin
    SetLength(OutBuffer, OutSize);
    result := Decode(InBuffer,  Length(InBuffer),   OutBuffer, FPassphrase, OutSize, FHeader);
    if result = 0 then
    begin
      if (Length(OutBuffer) <> OutSize) then
       SetLength(OutBuffer, OutSize);
    end
    else
      SetLength(OutBuffer, 0);
  end
  else
    SetLength(OutBuffer, 0);
end;

function TElPEMProcessor.PEMDecode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer) : integer;
begin
  result := Decode(InBuffer, InSize, OutBuffer, FPassphrase, OutSize, FHeader);
end;

function IsBase64UnicodeSequence(Buffer : pointer; Size : integer) : boolean;
var i : integer;
    eqcnt : integer;
begin
  result := true;
  i := 0;
  eqcnt := 0;
  while i <  Size  do
  begin
    if PByteArray(Buffer)[i + 1] <> 0 then
    begin
      result := false;
      exit;
    end;
    case Char(PByteArray(Buffer)[i]) of
      'A' .. 'Z',
      'a' .. 'z',
      '0' .. '9',
      '+',   '/':
        begin
          if eqcnt = 0 then
          begin
            inc(i, 2);
            continue;
          end
          else
          begin
            result := false;
            break;
          end;
        end;
      #0:
        begin
          if eqcnt > 0 then
          begin
            inc(i, 2);
            continue;
          end
          else
          begin
            result := false;
            break;
          end;
        end;
      #13, #10:
        begin
          inc(i, 2);
          continue;
        end;
      '=':
        begin
          if eqcnt < 2 then
          begin
            inc(eqcnt);
            inc(i, 2);
            Continue;
          end
          else
          begin
            result := false;
            exit;
          end;
        end;
      else
      begin
        result := false;
        exit;
      end;
    end;
  end;
end;

function IsBase64Sequence(Buffer : pointer; Size : integer) : boolean;
var i : integer;
    eqcnt : integer;
begin
  result := true;
  eqcnt := 0;
  for i := 0 to  Size  - 1 do
  begin
    case Char(PByteArray(Buffer)[i]) of
      'A' .. 'Z',
      'a' .. 'z',
      '0' .. '9',
      '+',   '/':
        begin
          if eqcnt = 0 then
            continue
          else
          begin
            result := false;
            break;
          end;
        end;
      #0:
        begin
          if eqcnt > 0 then
          begin
            continue;
          end
          else
          begin
            result := false;
            break;
          end;
        end;
      #13, #10:
        begin
          continue;
        end;
      '=':
        begin
          if eqcnt < 2 then
          begin
            inc(eqcnt);
            Continue;
          end
          else
          begin
            result := false;
            exit;
          end;
        end;
      else
      begin
        result := false;
        exit;
      end;
    end;
  end;
end;

function IsPEMSequence(Buffer : pointer; Size : integer) : boolean;
const
  PEMBeginStr : string = '-----BEGIN ';
var
  PEMBeginArr : ByteArray;
begin
  PEMBeginArr := EmptyArray;
  

  result := false;
  if  Size  < 11 then
    Exit;
  PEMBeginArr := BytesOfString(PEMBeginStr);
  Result :=
    CompareMem(@PEMBeginArr[0], Buffer, 11);

end;


{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  PEM_BUFFER_DEK_INFO := CreateByteArrayConst('DEK-Info:');

  PEM_BEGIN_CERTIFICATE_LINE := CreateByteArrayConst(PEM_BEGIN_CERTIFICATE_LINE_STR);
  PEM_END_CERTIFICATE_LINE := CreateByteArrayConst(PEM_END_CERTIFICATE_LINE_STR);

 {$endif}

end.
