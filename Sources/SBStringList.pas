(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBStringList;

interface

uses
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SysUtils,
  Classes;


  {$ifndef SB_EXCLUDE_EL_ALIASES}
  type ElStringList = TElStringList;
   {$endif}

{$ifdef SB_UNICODE_VCL}
type
  PByteArrayItem = ^TByteArrays;
  TByteArrays = array[0..MaxListSize] of ByteArray;
 {$endif}


type

  TElStringTokenizer =  class
  protected
    // internal fields
    FPosition : integer;
    FInQuote : boolean;

    FReturnEmptyTokens: Boolean;
    FDelimiters: string;
    FEscapeChar: Char;
    FOpeningQuote: Char;
    FClosingQuote: Char;
    FSourceString: string;
    FTrimQuotes: Boolean;
    FTrimSpaces: Boolean;
    function DoGetNext(CareForDelimiters: boolean; var Value : string) : boolean;
    procedure SetClosingQuote(const Value: Char);
    procedure SetReturnEmptyTokens(const Value: Boolean);
    procedure SetDelimiters(const Value: string);
    procedure SetEscapeChar(const Value: Char);
    procedure SetOpeningQuote(const Value: Char);
    procedure SetSourceString(const Value: string);
    procedure SetTrimQuotes(const Value: Boolean);
    procedure SetTrimSpaces(const Value: Boolean);
  public
    constructor Create;
    function GetAll : TElStringList;  overload; 
    procedure GetAll(ResultList : TElStringList);  overload; 
    function GetNext(var Value : string) : boolean;
    function GetRest(var Value : string) : boolean;
    procedure Reset;
    property ClosingQuote: Char read FClosingQuote write SetClosingQuote;
    property ReturnEmptyTokens: Boolean read FReturnEmptyTokens write
        SetReturnEmptyTokens;
    property Delimiters: string read FDelimiters write SetDelimiters;
    property EscapeChar: Char read FEscapeChar write SetEscapeChar;
    property OpeningQuote: Char read FOpeningQuote write SetOpeningQuote;
    property SourceString: string read FSourceString write SetSourceString;
    property TrimQuotes: Boolean read FTrimQuotes write SetTrimQuotes;
    property TrimSpaces: Boolean read FTrimSpaces write SetTrimSpaces;
  end;

implementation


constructor TElStringTokenizer.Create;
begin
  inherited;
  FDelimiters := '';
  FSourceString := '';
end;

procedure TElStringTokenizer.GetAll(ResultList : TElStringList);
var tmp : string;
begin
  while GetNext(tmp) do
    ResultList.Add(tmp);
end;

function TElStringTokenizer.GetAll : TElStringList;
begin
  result := TElStringList.Create;
  GetAll(Result);
end;

function TElStringTokenizer.DoGetNext(CareForDelimiters: boolean; var Value : string) : boolean;
var PrevPos : integer;
    LastToken : boolean;
begin
  result := false;
  LastToken := false;
  if FPosition > Length(FSourceString) - StringStartInvOffset then
    exit;
  PrevPos := FPosition;
  Value := '';
  while true do
  begin
    // check if we are out of line
    if FPosition > Length(FSourceString) - StringStartInvOffset then
      LastToken := true;

    if not LastToken then
    begin
      // check if we are in quote (if we are, we ignore delimiters)
      if FInQuote then
      begin
        // check for escape character
        if FSourceString[FPosition] = FEscapeChar then
        begin
          if (FPosition + 1 <= Length(FSourceString) - StringStartInvOffset) and
             (FSourceString[FPosition + 1] = FClosingQuote) then
          begin
            inc(FPosition);
          end
        end
        else
        if FSourceString[FPosition] = FClosingQuote then
        begin
          FInQuote := false;
        end;
        Value := Value + FSourceString[FPosition];
        inc(FPosition);
        continue;
      end
      else
      // maybe we've come across the opening quote
      if (FSourceString[FPosition] = FOpeningQuote) and (FClosingQuote <> #0) and (FOpeningQuote <> #0) then
      begin
        FInQuote := true;
        Value := Value + FSourceString[FPosition];
        inc(FPosition);
        continue;
      end;
    end;

    // check for delimiter
    if LastToken or
       (CareForDelimiters and (StringIndexOf(FDelimiters, FSourceString[FPosition]) >= StringStartOffset))
    then
    begin
      // empty token
      if FPosition = PrevPos then
      begin
        if ReturnEmptyTokens then
        begin
          inc(FPosition);
          result := true;
          break;
        end
        else
        begin
          Value := '';
          PrevPos := FPosition + 1;
          inc(FPosition);
          if LastToken then
            break
          else
            continue;
        end;
      end
      else
      begin
        (*
        {$ifndef SB_NET}
        Value := Copy(FSourceString, PrevPos, FPosition - PrevPos);
        {$else}
        Value := FSourceString.Substring(PrevPos, FPosition - PrevPos);
        {$endif}
        *)
        inc(FPosition);
        result := true;
        break;
      end;
    end;
    Value := Value + FSourceString[FPosition];

    inc(FPosition);
  end;

  if result then
  begin
    if TrimSpaces then
    begin
      Value := StringTrim(Value);
    end;
    if TrimQuotes and (Length(Value) >= 1) then
    begin
      if (Length(Value) >= 2) then
      begin
        if Value[Length(Value) - StringStartInvOffset] = FClosingQuote then
        begin
          Value := StringSubstring(Value, StringStartOffset, Length(Value)-1);
        end;
      end;

      if Value[StringStartOffset] = FOpeningQuote then
      begin
        Value := StringSubstring(Value, StringStartOffset + 1, Length(Value)-1);
      end;
    end;
  end;
end;

function TElStringTokenizer.GetRest(var Value : string) : boolean;
begin
  result := DoGetNext(false, Value);
end;

function TElStringTokenizer.GetNext(var Value : string) : boolean;
begin
  result := DoGetNext(true, Value);
end;

procedure TElStringTokenizer.Reset;
begin
  FPosition := StringStartOffset;
  FInQuote := false;
end;

procedure TElStringTokenizer.SetClosingQuote(const Value: Char);
begin
  FClosingQuote := Value;
  Reset;
end;

procedure TElStringTokenizer.SetReturnEmptyTokens(const Value: Boolean);
begin
  FReturnEmptyTokens := Value;
  Reset;
end;

procedure TElStringTokenizer.SetDelimiters(const Value: string);
begin
  FDelimiters := Value;
  Reset;
end;

procedure TElStringTokenizer.SetEscapeChar(const Value: Char);
begin
  FEscapeChar := Value;
  Reset;
end;

procedure TElStringTokenizer.SetOpeningQuote(const Value: Char);
begin
  FOpeningQuote := Value;
  Reset;
end;

procedure TElStringTokenizer.SetSourceString(const Value: string);
begin
  FSourceString := Value;
  Reset;
end;

procedure TElStringTokenizer.SetTrimQuotes(const Value: Boolean);
begin
  FTrimQuotes := Value;
  Reset;
end;

procedure TElStringTokenizer.SetTrimSpaces(const Value: Boolean);
begin
  FTrimSpaces := Value;
  Reset;
end;

end.
