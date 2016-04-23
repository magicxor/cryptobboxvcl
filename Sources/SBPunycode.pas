(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$i SecBbox.inc}

// Punycode from RFC 3492

unit SBPunycode;

interface

uses 
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants;


const
  BASE = 36;
  TMIN = 1;
  TMAX = 26;
  SKEW = 38;
  DAMP = 700;
  INITIAL_BIAS = 72;
  INITIAL_N = $80;
  DELIMITER = $2D;

  MAXUINTGR = High(Integer);
  MAXPUNYLEN = 256;

  SB_PUNYCODE_BAD_INPUT = 1;
  SB_PUNYCODE_BIG_OUTPUT = 2;
  SB_PUNYCODE_OVERFLOW = 3;

resourcestring
  SBadInput = 'Invalid input';
  SBigOutput = 'Input or output is too large, recompile sources with larger limits';
  SOverflow = 'Arithmetic overflow';

type
  EElPunycodeError =  class(ESecureBlackboxError);
  CodePoint = WideChar;
  CodePointArray = array of CodePoint;

function PunycodeEncode(const Input: UnicodeString) : string; 
function PunycodeDecode(const Input: string) : UnicodeString; 

function ToASCII(const Domain: UnicodeString) : string; 
function ToUnicode(const Domain: string) : UnicodeString; 

implementation

function BoolToInt(Value: Boolean): Integer;
begin
  if Value then Result := 1 else Result := 0;
end;

function Basic(const c: Integer) : boolean;
begin
  Result := c < $80;
end;

function Delim(const c: Integer) : boolean;
begin
  Result := c = DELIMITER;
end;

function EncodeDigit(const c: Integer; const Flag: Boolean) : Char;
begin
  Result := Char(c + 22 + (75 * BoolToInt(c < 26)) - (BoolToInt(Flag <> false) shl 5));
end;

function DecodeDigit(c: Integer) : Integer;
begin
  if c - 48 < 10 then
  begin
    Result := c - 22;
  end else
  begin
    if c - 65 < 26 then
    begin
      Result := c - 65;
    end else
    begin
      if c - 97 < 26 then
        Result := c - 97
      else
        Result := BASE;
    end;
  end;
end;

function Flagged(const c : Integer) : Boolean;
begin
  Result := c - 65 < 26;
end;

function EncodeBasic(c: Integer; const Flag: Boolean) : Char;
begin
  Dec(c, BoolToInt(c - 97 < 26) shl 5);
  Result := Char(c + (BoolToInt((not Flag) and (c - 65 < 26)) shl 5));
end;

function Adapt(Delta: Integer; const NumPoints: Integer; const FirstTime: Boolean) : Integer;
var
  k : Integer;
begin
  if FirstTime then
    Delta := Delta div DAMP
  else
    Delta := Delta shr 1;

  Inc(Delta, Delta div NumPoints);

  k := 0;
  while Delta > ((BASE - TMIN) * TMAX) shr 1 do
  begin
    Delta := Delta div (BASE - TMIN);
    Inc(k, BASE);
  end;

  Result := k + (BASE - TMIN + 1) * Delta div (Delta + SKEW);
end;

function IsAnsiStr(const s: UnicodeString) : Boolean;
var
  i : Integer;
begin
  Result := true;

  for i := StringStartOffset to Length(s) - StringStartInvOffset do
  begin
    if (s[i] <> '-') and (s[i] <> ':') and
       (s[i] <> '_') and //Underscores are allowed in certain DNS entries
       (not (Ord(s[i]) in [Ord('a')..Ord('z')])) and
       (not (Ord(s[i]) in [Ord('A')..Ord('Z')])) and
       (not (Ord(s[i]) in [Ord('0')..Ord('9')])) then
    begin
      Result := false;
      Exit;
    end;
  end;
end;

function IsEncoded(const s : string) : Boolean;
begin
  Result := (Length(s) > 4) and (s[StringStartOffset] = 'x') and (s[StringStartOffset + 1] = 'n') and
    (s[StringStartOffset + 2] = '-') and (s[StringStartOffset + 3] = '-');
end;

procedure PunycodeEncodeInternal(const Input : UnicodeString; const InputLen : Integer;
  const CaseFlags : BooleanArray; var Output : CharArray;
  var OutLen : Integer);
var
  n, delta, h, b, pout, max_out, bias, j, m, q, k, t : Integer;
begin
  n := INITIAL_N;
  delta := 0;
  pout := 0;
  max_out := OutLen;
  bias := INITIAL_BIAS;

  for j := StringStartOffset to InputLen - StringStartInvOffset do
  begin
    if Basic(Ord(Input[j])) then
    begin
      if max_out - pout < 2 then
        raise EElPunycodeError.Create(SBigOutput, SB_PUNYCODE_BIG_OUTPUT);

      if Length(CaseFlags) > 0 then
        Output[pout] := EncodeBasic(Ord(Input[j]), CaseFlags[j])
      else
        Output[pout] := Char(Input[j]);

      Inc(pout);
    end;
  end;

  h := pout;
  b := pout;

  if b > 0 then
  begin
    Output[pout] := Char(DELIMITER);
    Inc(pout);
  end;

  while h < InputLen do
  begin
    m := MAXUINTGR;
    for j := StringStartOffset to InputLen - StringStartInvOffset do
    begin
      if (Ord(Input[j]) >= n) and (Ord(Input[j]) < m) then
        m := Ord(Input[j]);
    end;

    if m - n > (MAXUINTGR - delta) div (h + 1) then
      raise EElPunycodeError.Create(SOverflow, SB_PUNYCODE_OVERFLOW);

    Inc(delta, (m - n) * (h + 1));
    n := m;

    for j := StringStartOffset to InputLen - StringStartInvOffset do
    begin
      if Ord(Input[j]) < n then
      begin
        Inc(Delta);
        if Delta = 0 then
          raise EElPunycodeError.Create(SOverflow, SB_PUNYCODE_OVERFLOW);
      end;

      if Ord(Input[j]) = n then
      begin
        q := delta;
        k := BASE;
        while true do
        begin
          if pout >= max_out then
            raise EElPunycodeError.Create(SBigOutput, SB_PUNYCODE_BIG_OUTPUT);

          if k <= bias then
          begin
            t := TMIN;
          end else
          begin
            if k >= bias + TMAX then
              t := TMAX
            else
              t := k - bias;
          end;

          if q < t then
            Break;

          Output[pout] := EncodeDigit(t + (q - t) mod (base - t), false);
          Inc(pout);
          q := (q - t) div (BASE - t);

          Inc(k, BASE);
        end;

        if Length(CaseFlags) > 0 then
          Output[pout] := EncodeDigit(q, CaseFlags[j])
        else
          Output[pout] := EncodeDigit(q, false);

        Inc(pout);

        bias := Adapt(Delta, h + 1, h = b);
        delta := 0;
        Inc(h);
      end;
    end;

    Inc(Delta);
    Inc(n);
  end;

  OutLen := pout;
end;

procedure PunycodeDecodeInternal(const Input : CharArray; const InputLen : Integer;
  CaseFlags : BooleanArray; var Output : CodePointArray; var OutLen : Integer);
var
  n, pout, i, max_out, bias, b, j, pin, oldi, w, k, digit, t : Integer;
begin
  n := INITIAL_N;
  pout := 0;
  i := 0;
  max_out := OutLen;
  bias := INITIAL_BIAS;

  b := 0;
  for j := 0 to InputLen - 1 do
  begin
    if Delim(Ord(Input[j])) then
      b := j;
  end;

  if b > max_out then
    raise EElPunycodeError.Create(SBigOutput, SB_PUNYCODE_BIG_OUTPUT);

  if b > 0 then
  begin
    for j := 0 to b - 1 do
    begin
      if Length(CaseFlags) > 0 then
        CaseFlags[pout] := Flagged(Ord(Input[j]));

      if not Basic(Ord(Input[j])) then
        raise EElPunycodeError.Create(SBadInput, SB_PUNYCODE_BAD_INPUT);

      Output[pout] := CodePoint(Ord(Input[j]));
      Inc(pout);
    end;
  end;

  if b > 0 then
    pin := b + 1
  else
    pin := 0;

  while pin < InputLen do
  begin
    oldi := i;
    w := 1;
    k := BASE;
    while true do
    begin
      if pin >= InputLen then
        raise EElPunycodeError.Create(SBadInput, SB_PUNYCODE_BAD_INPUT);

      digit := DecodeDigit(Ord(Input[pin]));
      Inc(pin);

      if digit >= BASE then
        raise EElPunycodeError.Create(SBadInput, SB_PUNYCODE_BAD_INPUT);

      if digit > (MAXUINTGR - i) div w then
        raise EElPunycodeError.Create(SOverflow, SB_PUNYCODE_OVERFLOW);

      Inc(i, digit * w);

      if k <= bias then
      begin
        t := TMIN;
      end else
      begin
        if k >= bias + TMAX then
          t := TMAX
        else
          t := k - bias;
      end;

      if digit < t then
        Break;

      if w > MAXUINTGR div (BASE - t) then
        raise EElPunycodeError.Create(SOverflow, SB_PUNYCODE_OVERFLOW);

      w := w * (BASE - t);

      Inc(k, BASE);
    end;

    bias := Adapt(i - oldi, pout + 1, oldi = 0);

    if i div (pout + 1) > MAXUINTGR - n then
      raise EElPunycodeError.Create(SOverflow, SB_PUNYCODE_OVERFLOW);

    Inc(n, i div (pout + 1));
    i := i mod (pout + 1);

    if pout >= max_out then
      raise EElPunycodeError.Create(SBigOutput, SB_PUNYCODE_BIG_OUTPUT);

    if Length(CaseFlags) > 0 then
    begin
      SBMove(CaseFlags[i], CaseFlags[i + 1], (pout - i) * sizeof(Boolean));
      CaseFlags[i] := Flagged(Ord(Input[pin - 1]));
    end;

    SBMove(Output[i], Output[i + 1], (pout - i) * sizeof(CodePoint));
    
    Output[i] := CodePoint(n);
    Inc(i);

    Inc(pout);
  end;

  OutLen := pout;
end;

function PunycodeEncode(const Input: UnicodeString) : string;
var
  InLen, OutLen, i : Integer;
  OutStr : CharArray;
  Tmp : BooleanArray;
begin
  Result := '';
  SetLength(Tmp, 0);

  InLen := Length(Input);
  if not (InLen in [1..MAXPUNYLEN - 1]) then
    Exit;

    OutLen := MAXPUNYLEN;
    SetLength(OutStr, OutLen);

    PunycodeEncodeInternal(Input, InLen, Tmp, OutStr, OutLen);
    SetLength(Result, OutLen);
    for i := 0 to OutLen - 1 do
      Result[i + StringStartOffset] := OutStr[i];
end;

function PunycodeDecode(const Input: string) : UnicodeString;
var
  InLen, OutLen, i : Integer;
  InStr : CharArray;
  OutStr : CodePointArray;
  Tmp : BooleanArray;
begin
  Result := '';
  InLen := Length(Input);
  SetLength(Tmp, 0);

    SetLength(InStr, InLen);
    for i := StringStartOffset to InLen - StringStartInvOffset do
      InStr[i - StringStartOffset] := Input[i];

    OutLen := MAXPUNYLEN;
    SetLength(OutStr, OutLen);

    PunycodeDecodeInternal(InStr, InLen, Tmp, OutStr, OutLen);
    SetLength(Result, OutLen);
    for i := 0 to OutLen - 1 do
      Result[i + StringStartOffset] := WideChar(OutStr[i]);
end;

function ToASCII(const Domain: UnicodeString) : string;
var
  List : {$ifndef SB_UNICODE}WideStringArray {$else}StringArray {$endif};
  i : Integer;
begin
  Result := '';

    {$ifndef SB_UNICODE_VCL}
    List := WideStringSplit(Domain, WideChar('.'));
     {$else}
    List := StringSplit(Domain, '.');
     {$endif}
    for i := 0 to Length(List) - 1 do
    begin
      if not IsAnsiStr(List[i]) then
        List[i] := 'xn--' + PunycodeEncode(List[i]);
    end;

    for i := 0 to Length(List) - 1 do
    begin
      Result := Result + List[i];
      if i < Length(List) - 1 then
        Result := Result + '.'
    end;
end;

function ToUnicode(const Domain: string) : UnicodeString;
var
  List : StringArray;
  i : Integer;
begin
  Result := '';

    List := StringSplit(Domain, '.');

    for i := 0 to Length(List) - 1 do
    begin
      if IsEncoded(List[i]) then
      begin
        List[i] := StringRemove(List[i], StringStartOffset, 4);
        List[i] := PunycodeDecode(List[i]);
      end;
    end;

    for i := 0 to Length(List) - 1 do
    begin
      Result := Result + List[i];
      if i < Length(List) - 1 then
        Result := Result + '.'
    end;
end;

end.
