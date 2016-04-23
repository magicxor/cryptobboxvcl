(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SBChSUnicode.inc}

unit SBChSUnicode;

interface


uses
  Classes,
  SBTypes,
  SBUtils,
  SBConstants;

type
  TPlCharType = (ctOther, ctLetterUpper, ctLetterLower, ctLetterTitle,
    ctLetterOther, ctNumber, ctPunctuation, ctSpace, ctControl, ctMark);

procedure WideUpperCase(var C: WideChar); overload;
function WideUpperCase(const S: UnicodeString): UnicodeString; overload;

procedure WideLowerCase(var C: WideChar); overload;
function WideLowerCase(const S: UnicodeString): UnicodeString; overload;

procedure WideTitleCase(var C: WideChar); overload;

function WideTitleCase(const S: UnicodeString): UnicodeString; overload;

function GetCharType(C: WideChar): TPlCharType;
(*
type
  TWideStringStream = class(TMemoryStream)
  protected
    function GetDataString: UnicodeString;
  public
    constructor Create(const aString: UnicodeString);

    property DataString: UnicodeString read GetDataString;
  end;
*)  

implementation





{$I SBChSUnicodeData.inc}

procedure WideUpperCase(var C: WideChar); overload;
var
  SubArray: PPlCaseSubArray;
begin
  SubArray := ToUpper[Word(C) shr CaseShift];
  if SubArray <> nil then
    C := SubArray^[Word(C) and CaseMask];
end;

function WideUpperCase(const S: UnicodeString): UnicodeString; overload;
var
  I, L: Integer;
begin
  L := Length(S);
  Result := S;
  for I := StringStartOffset to L - StringStartInvOffset do
    WideUpperCase(Result[I]);
end;

procedure WideLowerCase(var C: WideChar); overload;
var
  SubArray: PPlCaseSubArray;
begin
  SubArray := ToLower[Word(C) shr CaseShift];
  if SubArray <> nil then
    C := SubArray^[Word(C) and CaseMask];
end;

function WideLowerCase(const S: UnicodeString): UnicodeString; overload;
var
  I, L: Integer;
begin
  L := Length(S);
  Result := S;
  for I := StringStartOffset to L - StringStartInvOffset do
    WideLowerCase(Result[I]);
end;

procedure WideTitleCase(var C: WideChar); overload;
var
  SubArray: PPlCaseSubArray;
begin
  SubArray := ToTitle[Word(C) shr CaseShift];
  if SubArray <> nil then
    C := SubArray^[Word(C) and CaseMask];
end;

function WideTitleCase(const S: UnicodeString): UnicodeString; overload;
var
  I, L: Integer;
begin
  L := Length(S);
  Result := S;
  for I := StringStartOffset to L - StringStartInvOffset do
    WideTitleCase(Result[I]);
end;

function GetCharType(C: WideChar): TPlCharType;
var
  Item: PPlTypeArrayItem;
begin
  Item := @CharTypes[Word(C) shr TypeShift];
  if Item^.SubArray = nil then
    Result := Item^.RangeType
  else
    Result := TPlCharType(
      (Item^.SubArray[(Word(C) and TypeMask) shr 3] shr
      ((Word(C) and 7) * 4) and 15)
    );
end;

(*
{ TWideStringStream }

constructor TWideStringStream.Create(const aString: UnicodeString);
var
  StrLen: {$ifdef SB_CPU64}{$ifdef FPC}Int64{$else}Longint{$endif}{$else}Integer{$endif};
begin
  inherited Create;
  StrLen := Length(aString);
  if StrLen > 0 then
    begin
      StrLen := StrLen * SizeOf(WideChar);
      Realloc(StrLen);
      SBMove(Pointer(aString)^, Memory^, StrLen);
    end;
end;

function TWideStringStream.GetDataString: UnicodeString;
var
  StrLen: Integer;
begin
  StrLen := (Size + (SizeOf(WideChar) - 1)) div SizeOf(WideChar);
  SetLength(Result, StrLen);
  if StrLen > 0 then
    SBMove(Memory^, Pointer(Result)^, StrLen * SizeOf(WideChar));
end;
*)

end.
