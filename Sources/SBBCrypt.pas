(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBBCrypt;


interface
uses
  SBConstants,
  SBUtils,
  SBStrUtils,
  SBEncoding,
  SBBlowfish,
  SBTypes,
  SysUtils,
  SBRandom;


type

  TElBCrypt =  class
  protected
    class function EncryptRaw(Rounds : integer; const Password, Salt : ByteArray) : ByteArray;
    class function Base64Encode(const Value : ByteArray) : string;
    class function Base64Decode(const Value : string) : ByteArray;
  public
    class function GenerateSalt : ByteArray;
    class function EncryptPassword(const Password : string) : string;  overload; 
    class function EncryptPassword(const Password : string; Salt : ByteArray) : string;  overload; 
    class function EncryptPassword(const Password : string; Salt : ByteArray; Rounds : integer) : string;  overload; 
    class function CheckPassword (const Password, EncryptedPassword : string) : boolean;
  end;

  EElBCryptException =  class(ESecureBlackboxError);

resourcestring
  SInvalidRoundsNumber = 'Invalid rounds number';
  SInvalidSaltSize = 'Invalid salt size';
  SInvalidPasswordLength = 'Invalid password length';
  SInvalidBase64Encoding = 'Invalid Base-64 encoding';
  SInvalidEncryptedPassword = 'Invalid encrypted password';

implementation

const
  { BCrypt, due to unknown reasons, uses non-standard Base64 encoding }
  B64EncodeArray : array [0..63] of char =
     ( 
		    '.', '/', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
		    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
		    'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9'
     ) ;
  B64DecodeArray : array [0..127] of byte =
     ( 
		   $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff,
       $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff,
       $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff,
       $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff,
       $ff, $ff, $ff, $ff, $ff, $ff, $ff, $ff,
		   $ff, $ff, $ff, $ff, $ff, $ff,   0,   1,
        54,  55,  56,  57,  58,  59,  60,  61,
        62,  63, $ff, $ff, $ff, $ff, $ff, $ff,
       $ff,   2,   3,   4,   5,   6,   7,   8,
         9,  10,  11,  12,  13,  14,  15,  16,
		    17,  18,  19,  20,  21,  22,  23,  24,
        25,  26,  27, $ff, $ff, $ff, $ff, $ff,
       $ff,  28,  29,  30,  31,  32,  33,  34,
        35,  36,  37,  38,  39,  40,  41,  42,
        43,  44,  45,  46,  47,  48,  49,  50,
		    51,  52,  53, $ff, $ff, $ff, $ff, $ff
     ) ;



class function TElBCrypt.EncryptRaw(Rounds : integer; const Password, Salt : ByteArray) : ByteArray;
var
  i : integer;
  Ctx : TSBBlowfishContext;
  EncrData : array of cardinal;
begin
  if (Rounds < 4) or (Rounds > 31) then
    raise EElBCryptException.Create(SInvalidRoundsNumber);

  if Length(Salt) <> 16 then
    raise EElBCryptException.Create(SInvalidSaltSize);

  if Length(Password) = 0 then
    raise EElBCryptException.Create(SInvalidPasswordLength);

  SBBlowfish.EksInitialize(Ctx, Rounds, Salt, Password);

  SetLength(EncrData, 6);
  EncrData[0] := $4f727068;
  EncrData[1] := $65616e42;
  EncrData[2] := $65686f6c;
  EncrData[3] := $64657253;
  EncrData[4] := $63727944;
  EncrData[5] := $6f756274;

  for i := 0 to 63 do
  begin
    SBBlowfish.EncryptBlock(Ctx, EncrData[0], EncrData[1]);
    SBBlowfish.EncryptBlock(Ctx, EncrData[2], EncrData[3]);
    SBBlowfish.EncryptBlock(Ctx, EncrData[4], EncrData[5]);
  end;

  SetLength(Result, 24);
  for i := 0 to 23 do
    Result[i] := EncrData[i shr 2] shr ((3 - (i and 3)) * 8);
end;

class function TElBCrypt.GenerateSalt : ByteArray;
begin
  SetLength(Result, 16);
  SBRndGenerate( @Result[0] , 16);
end;

class function TElBCrypt.Base64Encode(const Value : ByteArray) : string;
var
  TmpVal, Res : ByteArray;
  i, k : integer;
begin
  try
    { filling with zeroes to 3-byte boundary }
    k := (3 - (Length(Value) mod 3)) mod 3;
    SetLength(TmpVal, Length(Value) + k);
    SBMove( Value[0], TmpVal[0] , Length(Value));
    for i := 1 to k do
      TmpVal[Length(TmpVal) - i] := 0;

    SetLength(Res, (Length(TmpVal) div 3) * 4);

    for i := 0 to (Length(TmpVal) div 3) - 1 do
    begin
      Res[i * 4] := Byte(B64EncodeArray[(TmpVal[i * 3] shr 2) and $3F]);
      Res[i * 4 + 1] := Byte(B64EncodeArray[((TmpVal[i * 3] shl 4) or (TmpVal[i * 3 + 1] shr 4)) and $3F]);
      Res[i * 4 + 2] := Byte(B64EncodeArray[((TmpVal[i * 3 + 1] shl 2) or (TmpVal[i * 3 + 2] shr 6)) and $3F]);
      Res[i * 4 + 3] := Byte(B64EncodeArray[TmpVal[i * 3 + 2] and $3F]);
    end;

    { cutting extra chars }
    SetLength(Res, Length(Res) - k);
    Result := StringOfBytes(Res);

  finally
    ReleaseArray(TmpVal);
    ReleaseArray(Res);
  end;
end;

class function TElBCrypt.Base64Decode(const Value : string) : ByteArray;
var
  i : integer;
  TmpVal : string;
  Bt : ByteArray;
begin
  Result := EmptyArray;


  if (Length(Value) mod 4) = 1 then
    raise EElBCryptException.Create(SInvalidBase64Encoding);

  for i := StringStartOffset to Length(Value) - StringStartInvOffset do
    if (Byte(Value[i]) > 127) or (B64DecodeArray[Byte(Value[i])] > 63) then
      raise EElBCryptException.Create(SInvalidBase64Encoding);

  { appending base64 zeroes to 4-char boundary }

  SetLength(Bt, 4);
  TmpVal := Value;
  while (Length(TmpVal) mod 4) > 0 do
    TmpVal := TmpVal + '.'; //
  SetLength(Result, (Length(TmpVal) shr 2) * 3);

  for i := 0 to (Length(TmpVal) shr 2) - 1 do
  begin
    Bt[0] := B64DecodeArray[Byte(TmpVal[i shl 2 + StringStartOffset])];
    Bt[1] := B64DecodeArray[Byte(TmpVal[i shl 2 + StringStartOffset + 1])];
    Bt[2] := B64DecodeArray[Byte(TmpVal[i shl 2 + StringStartOffset + 2])];
    Bt[3] := B64DecodeArray[Byte(TmpVal[i shl 2 + StringStartOffset + 3])];
    Result[i * 3] := (Bt[0] shl 2) or (Bt[1] shr 4);
    Result[i * 3 + 1] := (Bt[1] shl 4) or (Bt[2] shr 2);
    Result[i * 3 + 2] := (Bt[2] shl 6) or (Bt[3]);
  end;

  i := (4 - Length(Value) mod 4) mod 4;
  SetLength(Result, Length(Result) - i);

end;

class function TElBCrypt.EncryptPassword(const Password : string) : string;
begin
  Result := EncryptPassword(Password, GenerateSalt, 10);
end;

class function TElBCrypt.EncryptPassword(const Password : string; Salt : ByteArray) : string;
begin
  Result := EncryptPassword(Password, Salt, 10);
end;

class function TElBCrypt.EncryptPassword(const Password : string; Salt : ByteArray; Rounds : integer) : string;
var
  PassBytes : ByteArray;
  St : string;
begin
  try
  // adding zero char if we use version of salt '2a'. We do.
  PassBytes := (StrToUtf8(Password + #0));
  PassBytes := EncryptRaw(Rounds, PassBytes, Salt);
  SetLength(PassBytes, Length(PassBytes) - 1); // don't know why but we should do it

  St := IntToStr(Rounds);
  if Length(St) < 2 then
    St := '0' + St;

  Result := '$2a$' + St + '$' + Base64Encode(Salt) + Base64Encode(PassBytes);
  finally
    ReleaseArray(PassBytes);
  end;
end;

// TODO: test the code in VCL, .NET, Java and Delphi Mobile for different password lengths
class function TElBCrypt.CheckPassword (const Password, EncryptedPassword : string) : boolean;
var
  Rnd, StartOffset : integer;
  Salt, Pass : ByteArray;
  St, PassEncoded, NewPass : string;
  V2a : boolean;
begin
  try
    if Length(EncryptedPassword) < 27 then
      raise EElBCryptException.Create(SInvalidEncryptedPassword);

    if (EncryptedPassword[StringStartOffset] <> '$') or (EncryptedPassword[StringStartOffset + 1] <> '2') then
      raise EElBCryptException.Create(SInvalidEncryptedPassword);
    if EncryptedPassword[StringStartOffset + 2] = '$' then
    begin
      StartOffset := StringStartOffset + 3;
      V2a := false;
    end
    else if EncryptedPassword[StringStartOffset + 2] = 'a' then
    begin
      if EncryptedPassword[StringStartOffset + 3] <> '$' then
        raise EElBCryptException.Create(SInvalidEncryptedPassword);

      StartOffset := StringStartOffset + 4;
      V2a := true;
    end
    else
      raise EElBCryptException.Create(SInvalidEncryptedPassword);

    if EncryptedPassword[StartOffset + 2] <> '$' then
      raise EElBCryptException.Create(SInvalidEncryptedPassword);

    St := EncryptedPassword[StartOffset] + EncryptedPassword[StartOffset + 1];
    Rnd := StrToInt(St);

    if Length(EncryptedPassword) <> StartOffset + 55 + StringStartInvOffset then
      raise EElBCryptException.Create(SInvalidEncryptedPassword);

    St := StringSubstring(EncryptedPassword, StartOffset + 3, 22);
    Salt := Base64Decode(St);

    PassEncoded := StringSubstring(EncryptedPassword, StartOffset + 25, 31);

    if V2a then
      Pass := (StrToUtf8(Password + #0))
    else
      Pass := (StrToUtf8(Password));

    Pass := EncryptRaw(Rnd, Pass, Salt);
    SetLength(Pass, Length(Pass) - 1);
    NewPass := Base64Encode(Pass);

    Result :=  StringEquals(NewPass, PassEncoded);


  finally
    ReleaseArray(Salt);
    ReleaseArray(Pass);
  end;

end;

end.
