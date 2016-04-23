
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBRC2;

interface

uses
  SBTypes,
  SBConstants,
  SBUtils;

type

  TRC2Key =  array of byte;
  TRC2ExpandedKey =  array[0..63] of word;
  
const
  TRC2BufferSize = 8;
  TRC2ExpandedKeyLength = 64;

procedure ExpandKey(const Key: TRC2Key; out ExpandedKey: TRC2ExpandedKey); 
procedure Encrypt(var B0, B1 : cardinal; const ExpandedKey: TRC2ExpandedKey); 
procedure Decrypt(var B0, B1 : cardinal; const ExpandedKey: TRC2ExpandedKey); 

function ParseASN1Params(const Params : ByteArray; var IV : ByteArray;
  var KeyBits : integer): boolean; 
procedure WriteASN1Params(const IV : ByteArray; KeyBits : integer;
  var Params : ByteArray); 

implementation

uses
  SBASN1Tree;

const
  RC2Box: array[0..255] of byte =  ( 
    217, 120, 249, 196, 25, 221, 181, 237, 40, 233, 253, 121, 74, 160, 216, 157,
    198, 126, 55, 131, 43, 118, 83, 142, 98, 76, 100, 136, 68, 139, 251, 162,
    23, 154, 89, 245, 135, 179, 79, 19, 97, 69, 109, 141, 9, 129, 125, 50,
    189, 143, 64, 235, 134, 183, 123, 11, 240, 149, 33, 34, 92, 107, 78, 130,
    84, 214, 101, 147, 206, 96, 178, 28, 115, 86, 192, 20, 167, 140, 241, 220,
    18, 117, 202, 31, 59, 190, 228, 209, 66, 61, 212, 48, 163, 60, 182, 38,
    111, 191, 14, 218, 70, 105, 7, 87, 39, 242, 29, 155, 188, 148, 67, 3,
    248, 17, 199, 246, 144, 239, 62, 231, 6, 195, 213, 47, 200, 102, 30, 215,
    8, 232, 234, 222, 128, 82, 238, 247, 132, 170, 114, 172, 53, 77, 106, 42,
    150, 26, 210, 113, 90, 21, 73, 116, 75, 159, 208, 94, 4, 24, 164, 236,
    194, 224, 65, 110, 15, 81, 203, 204, 36, 145, 175, 80, 161, 244, 112, 57,
    153, 124, 58, 133, 35, 184, 180, 122, 252, 2, 54, 91, 37, 85, 151, 49,
    45, 93, 250, 152, 227, 138, 146, 174, 5, 223, 41, 16, 103, 108, 186, 201,
    211, 0, 230, 207, 225, 158, 168, 44, 99, 22, 1, 63, 88, 226, 137, 169,
    13, 56, 52, 27, 171, 51, 255, 176, 187, 72, 12, 95, 185, 177, 205, 46,
    197, 243, 219, 71, 229, 165, 156, 119, 10, 166, 32, 104, 254, 127, 193,
      173 ) ;

// Key expansion routine

procedure ExpandKey(const Key: TRC2Key; out ExpandedKey: TRC2ExpandedKey);
var
  I, KeySize: integer;
  EfLen: cardinal;
  T8: integer;
  TM: byte;
  TmpKey : array [0..127] of byte;
begin
  KeySize := Length(Key);

  if (KeySize <= 0) or (KeySize > 128) then
    raise EElEncryptionError.CreateFmt(SInvalidKeySize, [KeySize shl 3]);

  EfLen := KeySize shl 3;

  for i := 0 to 127 do
    TmpKey[i] := 0;

  for i := 0 to KeySize - 1 do
    TmpKey[i] := Key[i];

  for I := KeySize to 127 do
    TmpKey[I] := RC2Box[(TmpKey[I - KeySize] + TmpKey[I - 1]) and $FF];

  // Ported from C
  T8 := (EfLen + 7) shr 3;
  TM := 255 shr ((8 - (EfLen mod 8)) mod 8);
  TmpKey[128 - T8] := RC2Box[TmpKey[128 - T8] and TM];

  for i := 127 - T8 downto 0 do
    TmpKey[i] := RC2Box[TmpKey[i + 1] xor TmpKey[i + T8]];

  for i := 0 to 63 do
    ExpandedKey[i] := TmpKey[i shl 1] + word(TmpKey[i shl 1 + 1] shl 8);
end;

// Block processing routines

procedure Encrypt(var B0, B1 : cardinal; const ExpandedKey: TRC2ExpandedKey);
var
  T0, T1, T2, T3: word;
  I: integer;
begin
  T0 := B0;
  T1 := B0 shr 16;
  T2 := B1;
  T3 := B1 shr 16;
  
  for I := 0 to 15 do
  begin
    { changed from Inc() since of buggy Chrome compiler - error in Xamarin assemblies}
    T0 := T0 + (T1 and not T3) + (T2 and T3) + ExpandedKey[I shl 2];
    T0 := (T0 shl 1) or (T0 shr 15);
    T1 := T1 + (T2 and not T0) + (T3 and T0) + ExpandedKey[I shl 2 + 1];
    T1 := (T1 shl 2) or (T1 shr 14);
    T2 := T2 + (T3 and not T1) + (T0 and T1) + ExpandedKey[I shl 2 + 2];
    T2 := (T2 shl 3) or (T2 shr 13);
    T3 := T3 + (T0 and not T2) + (T1 and T2) + ExpandedKey[I shl 2 + 3];
    T3 := (T3 shl 5) or (T3 shr 11);
    if (I = 4) or (I = 10) then
    begin
      T0 := T0 + ExpandedKey[T3 and $3F];
      T1 := T1 + ExpandedKey[T0 and $3F];
      T2 := T2 + ExpandedKey[T1 and $3F];
      T3 := T3 + ExpandedKey[T2 and $3F];
    end;
  end;

  B0 := T0 or (T1 shl 16);
  B1 := T2 or (T3 shl 16);
end;

procedure Decrypt(var B0, B1 : cardinal; const ExpandedKey: TRC2ExpandedKey);
var
  T0, T1, T2, T3: word;
  I: integer;
begin
  T0 := B0;
  T1 := B0 shr 16;
  T2 := B1;
  T3 := B1 shr 16;
  
  for I := 15 downto 0 do
  begin
    { changed from Dec() since of buggy Chrome compiler - error in Xamarin assemblies }
    T3 := (T3 shr 5) or (T3 shl 11);
    T3 := T3 - ((T0 and not T2) + (T1 and T2) + ExpandedKey[I shl 2 + 3]);
    T2 := (T2 shr 3) or (T2 shl 13);
    T2 := T2 - ((T3 and not T1) + (T0 and T1) + ExpandedKey[I shl 2 + 2]);
    T1 := (T1 shr 2) or (T1 shl 14);
    T1 := T1 - ((T2 and not T0) + (T3 and T0) + ExpandedKey[I shl 2 + 1]);
    T0 := (T0 shr 1) or (T0 shl 15);
    T0 := T0 - ((T1 and not T3) + (T2 and T3) + ExpandedKey[I shl 2]);

    if (I = 5) or (I = 11) then
    begin
      T3 := T3 - ExpandedKey[T2 and $3F];
      T2 := T2 - ExpandedKey[T1 and $3F];
      T1 := T1 - ExpandedKey[T0 and $3F];
      T0 := T0 - ExpandedKey[T3 and $3F];
    end;
  end;

  B0 := T0 or (T1 shl 16);
  B1 := T2 or (T3 shl 16);
end;


function ParseASN1Params(const Params : ByteArray; var IV : ByteArray;
  var KeyBits : integer): boolean;
var
  Tag, SeqTag : TElASN1ConstrainedTag;
  Index : integer;
  Ver : integer;
begin
  Result := false;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(@Params[0], Length(Params)) then
      Exit;
    if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      Exit;
    SeqTag := TElASN1ConstrainedTag(Tag.GetField(0));
    Index := 0;
    if SeqTag.Count < 1 then
      Exit;
    if SeqTag.GetField(0).CheckType(SB_ASN1_INTEGER, false) then
    begin
      Ver := ASN1ReadInteger(TElASN1SimpleTag(SeqTag.GetField(0)));
      if Ver = 160 then
        KeyBits := 40
      else if Ver = 120 then
        KeyBits := 64
      else if Ver = 58 then
        KeyBits := 128
      else if Ver >= 256 then
        KeyBits := Ver
      else
        Exit;
      Inc(Index);
    end
    else
      KeyBits := 32;
    if Index >= SeqTag.Count then
      Exit;
    if SeqTag.GetField(Index).CheckType(SB_ASN1_OCTETSTRING, false) then
      IV := TElASN1SimpleTag(SeqTag.GetField(Index)).Content
    else
      Exit;    
    Result := true;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure WriteASN1Params(const IV : ByteArray; KeyBits : integer;
  var Params : ByteArray);
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Ver : integer;
  Size : integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.TagId := SB_ASN1_SEQUENCE;
    if KeyBits <> 32 then
    begin
      if KeyBits = 40 then
        Ver := 160
      else if KeyBits = 64 then
        Ver := 120
      else if KeyBits = 128 then
        Ver := 58
      else
        Ver := KeyBits;
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      ASN1WriteInteger(STag, Ver);
    end;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;
    STag.Content := IV;
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(Params, Size);
    Tag.SaveToBuffer( @Params[0] , Size);
    SetLength(Params, Size);
  finally
    FreeAndNil(Tag);
  end;
end;

end.
