(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBUnicode;

interface

uses
  {$ifndef SB_UNICODE_VCL}
  SBChSConv,
  SBChSConvCharsets,
  {$ifndef SB_REDUCED_CHARSETS}
  SBChSCJK,
   {$endif}
   {$endif}
  SysUtils,
  {$ifdef SB_WINDOWS}
  Windows,
   {$endif}
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants;


type
  TElUnicodeConverter = class(TElStringConverter)
  protected
    { 4 converters - for faster conversion }
    {$ifndef SB_UNICODE_VCL}
    FAnsiToUtf8 : TPlConverter;
    FUtf8ToAnsi : TPlConverter;
    FAnsiToUnicode : TPlConverter;
    FUnicodeToAnsi : TPlConverter;
     {$endif}

    procedure SetDefCharset(const Value : string); override;
  public
    constructor Create;
     destructor  Destroy; override;

    function StrToUtf8(const Source : string) : ByteArray; override;
    function Utf8ToStr(const Source : ByteArray) : string; override;
    function StrToWideStr(const Source : string) : ByteArray; override;
    function WideStrToStr(const Source : ByteArray) : string; override;
  end;


function CreateUnicodeStringConverter() : TElStringConverter; 

implementation


function CreateUnicodeStringConverter() : TElStringConverter;
begin
  // Alter this method to return NIL if Unicode support is not available for
  // some platform.
  Result := TElUnicodeConverter.Create();
end;

{ TElUnicodeConverter }

constructor TElUnicodeConverter.Create;
begin
  inherited Create;

  {$ifdef SB_WINDOWS}
  FDefCharset := IntToStr(GetACP);
   {$else}
  FDefCharset := 'iso-8859-1';
   {$endif}
  
  {$ifndef SB_UNICODE_VCL}
  FAnsiToUtf8 := TPlConverter.Create;
  FAnsiToUtf8.SrcCharsetName := FDefCharset;
  FAnsiToUtf8.DstCharsetName := 'utf8';

  FUtf8ToAnsi := TPlConverter.Create;
  FUtf8ToAnsi.SrcCharsetName := 'utf8';
  FUtf8ToAnsi.DstCharsetName := FDefCharset;

  FAnsiToUnicode := TPlConverter.Create;
  FAnsiToUnicode.SrcCharsetName := FDefCharset;
  FAnsiToUnicode.DstCharsetName := 'unicode';

  FUnicodeToAnsi := TPlConverter.Create;
  FUnicodeToAnsi.SrcCharsetName := 'unicode';
  FUnicodeToAnsi.DstCharsetName := FDefCharset;
   {$endif}
end;

 destructor  TElUnicodeConverter.Destroy;
begin
  {$ifndef SB_UNICODE_VCL}
  FreeAndNil(FAnsiToUtf8);
  FreeAndNil(FUtf8ToAnsi);
  FreeAndNil(FAnsiToUnicode);
  FreeAndNil(FUnicodeToAnsi);
   {$endif}

  inherited;
end;

procedure TElUnicodeConverter.SetDefCharset(const Value : string);
begin
  FDefCharset := Value;

  {$ifndef SB_UNICODE_VCL}
  FAnsiToUtf8.SrcCharsetName := FDefCharset;
  FUtf8ToAnsi.DstCharsetName := FDefCharset;
  FAnsiToUnicode.SrcCharsetName := FDefCharset;
  FUnicodeToAnsi.DstCharsetName := FDefCharset;
   {$endif}
end;

function TElUnicodeConverter.StrToUtf8(const Source : string) : ByteArray;
{$ifdef SB_ANSI_VCL}
var TmpStr : AnsiString;
 {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  {$ifndef SB_UNICODE_VCL}
  FAnsiToUtf8.Convert(Source, TmpStr, []);
  Result := BytesOfAnsiString(TmpStr);
   {$else}
  //Result := UTF8Encode(Source); -- commented by EM, 7/05/2013, during iOS adaptation
  ConvertUTF16ToUTF8(Source, Result, lenientConversion, false);
   {$endif}


 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function TElUnicodeConverter.Utf8ToStr(const Source : ByteArray) : string;
{$ifdef SB_ANSI_VCL}
var TmpStr : AnsiString;
 {$endif}
begin
  {$ifndef SB_UNICODE_VCL}
  TmpStr := AnsiStringOfBytes(Source);
  FUtf8ToAnsi.Convert(TmpStr, Result, []);
   {$else}
  //Result := UTF8ToUnicodeString(Source);
  ConvertUTF8ToUTF16(Source, Result, lenientConversion, false);
   {$endif}


end;

function TElUnicodeConverter.StrToWideStr(const Source : string) : ByteArray;
{$ifdef SB_ANSI_VCL}
var TmpStr : AnsiString;
 {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  {$ifndef SB_UNICODE_VCL}
  FAnsiToUnicode.Convert(Source, TmpStr, []);
  Result := BytesOfAnsiString(TmpStr);
   {$else}
  SetLength(Result, Length(Source) * SizeOf(Char));

  SBMove(Source[StringStartOffset], Result[0], Length(Result));
  //SwapBigEndianWords(@Result[1], Length(Result));
   {$endif}
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function TElUnicodeConverter.WideStrToStr(const Source : ByteArray) : string;
{$ifdef SB_UNICODE_VCL}
var
  Buf : ByteArray;
 {$endif}
{$ifdef SB_ANSI_VCL}
var TmpStr : AnsiString;
 {$endif}
begin
  {$ifndef SB_UNICODE_VCL}
  TmpStr := AnsiStringOfBytes(Source);
  FUnicodeToAnsi.Convert(TmpStr, Result, []);
   {$else}
  Buf := Copy(Source, 0, Length(Source));
  //SwapBigEndianWords(@Buf[1], Length(Buf));
  SetLength(Result, Length(Buf) shr 1);
  SBMove(Buf[0], Result[StringStartOffset], Length(Buf));
   {$endif}
end;

end.
