(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBRandom;

interface

uses
  SBMath,
    SysUtils,
    Classes,
    {$ifdef SB_WINDOWS}
    Windows,
     {$endif}
    {$ifdef SB_UNIX}
      {$ifdef FPC}
      unix,
      unixtype,
      {$ifdef SB_LINUX}
      {$ifndef SB_ANDROID} 
      pthreads,
       {$endif}
      linux,
       {$endif}
       {$else FPC}
      Posix.Base,
      Posix.Fcntl,
      Posix.SysTime,
      Posix.SysTimes,
      Posix.SysTypes,
      Posix.Time,
       {$endif}
     {$endif}
  SBTypes,
  SBUtils,
  SBStreams;


type

  TElRandom = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElRandom = TElRandom;
   {$endif}

  TElRandom = class
  private
    S : array[0..255] of byte;
    CI, CJ : integer;
  public
    constructor Create;  overload; 
    constructor Create(TimeSeed :  LongWord );  overload;  // for pseudo-random generation (no time seed)
    destructor Destroy; override;

    procedure Randomize(const Seed : ByteArray);  overload; 

    {$ifdef SB_WINDOWS}
    procedure Randomize(Stream : TElStream; Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
     {$endif}
    
    function Generate(Count : integer) : ByteArray;  overload; 
    procedure Randomize(Buffer : pointer; Count : integer); overload;
    procedure Generate(Buffer : pointer; Count : integer); overload;
    procedure Seed(Buffer: pointer; Count : integer);

    {$ifdef SB_WINDOWS}
    procedure Generate(Stream : TStream; Count : integer); overload;
     {$endif}
  end;

{ Random wrappers }

function SBRndTimeSeed : Longint; 

procedure SBRndInit; 
procedure SBRndCreate; 
procedure SBRndDestroy; 
procedure SBRndSeed(const Salt : string {$ifdef HAS_DEF_PARAMS} =  '' {$endif});  overload; procedure SBRndSeed(Buffer: pointer; Size: integer); overload;
procedure SBRndSeedTime; 
procedure SBRndGenerate(Buffer: pointer; Size: integer); overload;
function SBRndGenerate(UpperBound: cardinal {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): cardinal;  overload; procedure SBRndGenerateLInt(A : PLInt; Bytes : integer); 

procedure SBRndRandomize(const Seed: ByteArray); 

implementation

uses
  SyncObjs,
  Math,
  SBConstants,
  SBStrUtils,
  SBSHA, 
  SBSHA2; 

type
  PByte = ^byte;

{$ifndef SB_MSSQL}
var
  FGlobalRandom : TElRandom  =  nil;
  {$ifndef SB_NO_NET_RWLOCK}
  FRndCriticalSection :  TCriticalSection ;
   {$else}
  // use Monitor.Enter/Exit(FGlobalRandom)
   {$endif}
 {$endif}

{$ifdef SB_MACOS}
{$ifdef DELPHI_MAC}
function  arc4random() : DWORD; cdecl; external '/usr/lib/libc.dylib' name '_arc4random';
 {$else}
function  arc4random() : DWORD; cdecl; external 'c';
 {$endif}

{$ifndef SB_iOS}
const
  CarbonCoreLib = '/System/Library/Frameworks/CoreServices.framework/Frameworks/CarbonCore.framework/CarbonCore';
{$ifndef FPC}
function UpTime: UInt64; cdecl external CarbonCoreLib name 'UpTime';
function AbsoluteToNanoseconds(absoluteTime: UInt64): UInt64; cdecl external CarbonCoreLib name 'AbsoluteToNanoseconds';
 {$else}
function UpTime: UInt64; external name '_UpTime';
function AbsoluteToNanoseconds(absoluteTime: UInt64): UInt64; external name '_AbsoluteToNanoseconds';
 {$endif}
 {$endif}
 {$endif}

{$ifdef SB_UNIX}
function ReadDevRandom : integer;
var
  f : file of integer;
  i : integer;
begin
  i        := 0;
  filemode := 0;
  AssignFile(f, '/dev/urandom');
  reset (f {$ifndef DELPHI_MAC},1 {$endif});
  read (f,i);
  CloseFile (f);
  RandSeed := i;
end;
 {$endif}

constructor TElRandom.Create; {$ifdef SB_ANDROID} overload;  {$endif}
var
  {$ifdef SB_WINDOWS}
  D : longword;
   {$else}
  D : TDateTime;
   {$endif}
begin
  inherited;
  {$ifdef SB_WINDOWS}
  D := GetTickCount();
   {$else}
  D := Now;
   {$endif}
  Randomize(@D, SizeOf(D));
end;

constructor TElRandom.Create(TimeSeed :  LongWord ); {$ifdef SB_ANDROID} overload;  {$endif}
begin
  inherited Create;
  Randomize(@TimeSeed, SizeOf(TimeSeed));
end;

destructor TElRandom.Destroy;
begin
  inherited;
end;

procedure TElRandom.Randomize(const Seed : ByteArray);
var
  I: Integer;
  C: Byte;
  K: array[0..255] of Byte;
  L, J: Word;
  P: Byte;
begin
  for I := 0 to 255 do
    S[I] := Byte(I);

  L := 0;
  J := 0;
  C := 0;
  while (J < 256) do
  begin
    K[J] := (Byte(Seed[L]) shr C) and 255;
    Inc(C);
    if C > 3 then
    begin
      Inc(L);
      C := 0;
    end;

    if (Integer(L) >= Length(Seed)) then L := 0;
    Inc(J);
  end;
  CJ := 0;
  for I := 0 to 255 do
  begin
    CJ := (CJ + S[I] + K[I]) mod 256;
    P := S[I];
    S[I] := S[CJ];
    S[CJ] := P;
  end;
  CJ := 0;
  CI := 0;
end;

{$ifdef SB_WINDOWS}
procedure TElRandom.Randomize(Stream : TElStream; Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  S : ByteArray;
begin
  if Count = 0 then
  begin
    Stream.Position := 0;
    Count := Stream.Size;
  end
  else
    Count := Math.Min(integer(Stream.Size - Stream.Position), Count);

  SetLength(S, Count);

  Stream.ReadBuffer(S[0], Length(S));
  Randomize(S);
end;
 {$endif}

procedure TElRandom.Randomize(Buffer : pointer; Count : integer);
var
  St: ByteArray;
begin
  SetLength(St, Count);
  SBMove(Buffer^, St[0], Length(St));
  Randomize(St);
end;

procedure TElRandom.Generate(Buffer : pointer; Count : integer);
var
  P: Byte;
  T: Word;
  Pb : PByte;
begin
  Pb := Buffer;
  while Count > 0 do
  begin
    CI := (Word(CI) + 1) mod 256;
    CJ := (Word(CJ) + Word(S[CI])) mod 256;
    P := S[CI];
    S[CI] := S[CJ];
    S[CJ] := P;
    T := (Word(S[CI]) + Word(S[CJ])) mod 256;
    Pb^ := S[T];
    Inc(Pb);
    Dec(Count);
  end;
end;


function TElRandom.Generate(Count : integer) : ByteArray;
begin
  SetLength(Result, Count);
  Generate(@Result[0], Count);
end;

procedure TElRandom.Seed(Buffer: pointer; Count : integer);
var
  I: Integer;
  C: Byte;
  K: array[0..255] of Byte;
  L, J: Word;
  P: Byte;
begin
  if  Count  = 0 then
    Exit;
  J := 0;
  L := 0;
  C := 0;
  while (J < 256) do
  begin
    K[J] := (Byte(PByteArray(Buffer)[L]) shr C) and 255;

    Inc(C);
    if C > 3 then
    begin
      Inc(L);
      C := 0;
    end;
    if (L >= Count) then
      L := 0;
    Inc(J);
  end;
  CJ := 0;
  for I := 0 to 255 do
  begin
    CJ := (CJ + S[I] + K[I]) mod 256;
    P := S[I];
    S[I] := S[CJ];
    S[CJ] := P;
  end;
  CJ := 0;
  CI := 0;
end;

{$ifdef SB_WINDOWS}
procedure TElRandom.Generate(Stream : TStream; Count : integer);
var
  Buf : array of byte;
begin
  SetLength(Buf, Count);
  Generate(@Buf[0], Length(Buf));
  Stream.WriteBuffer(Buf[0], Length(Buf));
end;
 {$endif}



{$ifdef SB_WINDOWS}
function SBRndTimeSeed : Longint;
var
  Counter: Int64;
begin
  if QueryPerformanceCounter(Counter) then
    Result := Counter
  else
    Result := GetTickCount;
end;
 {$endif}

{$ifdef SB_UNIX}
function SBRndTimeSeed : Longint;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
var
  TimeOfDay: timeval;
 {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if {$ifdef FPC}fpgettimeofday {$else}gettimeofday {$endif}({$ifdef FPC}@ {$endif}TimeOfDay, nil) = 0 then
    Result := TimeOfDay.tv_sec * 1000000 + TimeOfDay.tv_usec
  else
    Result := ReadDevRandom;
 {$endif}
end;
 {$endif SB_UNIX}
(*
{$ifdef SB_MACOS}
function SBRndTimeSeed : Longint;
begin
//  {$ifndef SB_iOS}
//  Result := AbsoluteToNanoseconds(UpTime) div 1000000;
//  {$else}
  Result := LongInt(arc4random());
//  {$endif}
end;
{$endif SB_MACOS}
*)
procedure SBRndInit;
begin
  SBRndCreate;
  SBRndSeed('initialization');
  SBRndSeedTime;
end;

procedure SBRndCreate;
begin
  {$ifndef SB_MSSQL}
  if FGlobalRandom <> nil then
    FreeAndNil(FGlobalRandom);
  FGlobalRandom := TElRandom.Create;
  FRndCriticalSection := TCriticalSection.Create;
   {$else}
  if Globals.GlobalRandom <> nil then
    Globals.GlobalRandom := nil;
  Globals.GlobalRandom := TElRandom.Create;
  Globals.RndCriticalSection := ReaderWriterLock.Create;
   {$endif}
end;

procedure SBRndDestroy;
begin
  {$ifndef SB_MSSQL}
    {$ifndef SB_NO_JAVA_RWLOCK}
    FreeAndNil(FRndCriticalSection);
     {$endif}
    FreeAndNil(FGlobalRandom);
   {$else}
  Globals.GlobalRandom := nil;
  Globals.RndCriticalSection := nil;
   {$endif}
end;

procedure SBRndSeed(const Salt : string {$ifdef HAS_DEF_PARAMS} =  '' {$endif});  overload; 
var
  A : cardinal;
  B :  array [0..1]  of byte ;
  D :  double ;
  I, J : integer;
  M : TMessageDigest256;
  {$ifdef SB_UNICODE_VCL}
  SaltBuf : ByteArray;
   {$endif}
  Ctx : TSHA256Context;
begin

  FRndCriticalSection.Enter;

  FillChar(M, 20, 63);
  {$ifdef SB_UNICODE_VCL}
  ConvertUTF16ToUTF8(Salt, SaltBuf, strictConversion, false);//SaltBuf := UTF8Encode(Salt);
   {$endif}
  for I := 0 to 15 do
  begin
    A := GetTickCount;
    D := Now;
    B[0] := (A shr 24) xor (A and $ff);
    B[1] := ((A shr 16) and $ff) xor ((A shr 8) and $ff);
    InitializeSHA256(Ctx);
    HashSHA256(Ctx, @M, 20);
    for J := 0 to 1023 do
    begin
      HashSHA256(Ctx, @A, 4);
      HashSHA256(Ctx, @D, 8);
      HashSHA256(Ctx, @B[0], 2);
      {$ifndef SB_UNICODE_VCL}
      HashSHA256(Ctx, @Salt[1], Length(Salt));
       {$else}
      HashSHA256(Ctx, @SaltBuf[1], Length(SaltBuf));
       {$endif}
    end;
    M := FinalizeSHA256(Ctx);
    FGlobalRandom.Seed(@M, 20);
  end;
  FRndCriticalSection.Leave;
end;

procedure SBRndSeed(Buffer: pointer; Size: integer); overload;
begin
  FRndCriticalSection.Enter;
  
  {$ifndef SB_MSSQL}
  FGlobalRandom.Seed(Buffer , Size );
   {$else}
  TElRandom(Globals.GlobalRandom).Seed(Buffer , Size );
   {$endif}
  FRndCriticalSection.Leave;
end;

procedure SBRndSeedTime;
var
  C : cardinal;
  D : double;
  A :  array [0..47]  of byte ;
begin
  C := GetTickCount;
  D := Now;
  SBMove(C, A[0], 4);
  SBMove(D, A[4], 8);
  SBMove(C, A[12], 4);
  SBMove(D, A[16], 8);
  SBMove(C, A[24], 4);
  SBMove(D, A[28], 8);
  SBMove(C, A[36], 4);
  SBMove(D, A[40], 8);
  SBRndSeed(@A[0], 48);
end;

procedure SBRndGenerate(Buffer: pointer; Size: integer);  overload; 
begin
  FRndCriticalSection.Enter;
  
  {$ifndef SB_MSSQL}
  FGlobalRandom.Generate(Buffer, Size);
   {$else}
  TElRandom(Globals.GlobalRandom).Generate(Buffer, Size);
   {$endif}
  FRndCriticalSection.Leave;
end;


function SBRndGenerate(UpperBound: cardinal{$ifdef HAS_DEF_PARAMS} =  0 {$endif}): cardinal;  overload; 
begin
  SBRndGenerate(@Result, 4);
  if UpperBound <> 0 then
    Result := Result mod UpperBound;
end;

procedure SBRndGenerateLInt(A : PLInt; Bytes : integer);
var
  I : integer;
  Tm: TSBInt64;
begin
  A.Length := Bytes shr 2 + 1;
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  for I := 1 to A.Length - 1 do
  begin
    A.Digits[I] := 0;
    Tm := SBRndGenerate(256);
    A.Digits[I] := A.Digits[I] or Tm;
    Tm := SBRndGenerate(256);
    A.Digits[I] := A.Digits[I] or (Tm shl 8);
    Tm := SBRndGenerate(256);
    A.Digits[I] := A.Digits[I] or (Tm shl 16);
    Tm := SBRndGenerate(256);
    A.Digits[I] := A.Digits[I] or (Tm shl 24);
  end;
  A.Digits[A.Length] := 0;
  for I := 1 to (Bytes mod 4) do
  begin
    A.Digits[A.Length] := A.Digits[A.Length] or (TSBInt64(SBRndGenerate(256))
      shl ((I - 1) shl 3));
  end;
  if (Bytes mod 4) = 0 then A.Length := A.Length - 1;
end;

procedure SBRndRandomize(const Seed: ByteArray);
begin
  FRndCriticalSection.Enter;
  
  {$ifndef SB_MSSQL}
  FGlobalRandom.Randomize(Seed);
   {$else}
  TElRandom(Globals.GlobalRandom).Randomize(Seed);
   {$endif}
  
  FRndCriticalSection.Leave;
end;


end.
