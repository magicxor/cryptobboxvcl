(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBPKIAsync;

interface

{$ifndef SB_NO_PKIASYNC}

uses
  {$ifdef WIN32}
  Windows,
   {$endif}
  SyncObjs,
  Classes,
  SysUtils,
  SBElgamal,
  SBDSA,
  SBTypes,
  SBUtils,
  SBConstants,
  SBMath,
  SBRSA;

type
  TSBPublicKeyComputationTokenType =  (
    ttElgamalEncrypt,
    ttElgamalSign,
    ttDSASign,
    ttPrimeGeneration,
    ttDSAGeneration,
    ttRSAGeneration,
    ttElgamalGeneration
  ); 

  TElPublicKeyAsyncCalculator =  class;
  
  TElPublicKeyComputationToken = class
   private 
    FThread :  TThread ;
    FThreadFinished : boolean;
    FOwner : TElPublicKeyAsyncCalculator;
    FTokenType : TSBPublicKeyComputationTokenType;
    FLIntArray : array[0..7] of PLInt;
    FElgA : PLInt;
    FElgP : PLInt;
    FElgQ : PLInt;
    FElgR : PLInt;
    FElgT1 : PLInt;
    FElgT2 : PLInt;
    FElgT3 : PLInt;
    FElgKInv : PLInt;
    FPrime : PLInt;
    FRSAM : PLInt;
    FRSAPrivExp : PLInt;
    FRSAPubExp : PLInt;
    FRSAPrime1 : PLInt;
    FRSAPrime2 : PLInt;
    FRSAExp1 : PLInt;
    FRSAExp2 : PLInt;
    FRSACoeff : PLInt;
    FDSAP : PLInt;
    FDSAQ : PLInt;
    FDSAG : PLInt;
    FDSAY : PLInt;
    FDSAX : PLInt;
    FDSAT1 : PLInt;
    FDSAR : PLInt;
    FDSAK : PLInt;
    FKeyBlob : ByteArray;
    FData :  pointer ;
    procedure OnThreadTerminate(Sender: TObject);
    function GetFinished : boolean;
  protected
    procedure BeginElgamalEncryption(P, G, Y : PLInt);
    procedure BeginElgamalSigning(P, G : PLInt);
    procedure BeginPrimeGeneration(Bits : integer);
    procedure BeginDSASigning(P, Q, G : PLInt);
    procedure BeginRSAGeneration(Bits : integer);
    procedure BeginDSAGeneration(Bits : integer);
    procedure BeginElgamalGeneration(Bits : integer);
    procedure Start;
    procedure Resume;
    procedure Stop;
    procedure  Wait ;
  public
    constructor Create(TokenType : TSBPublicKeyComputationTokenType;
      Owner : TElPublicKeyAsyncCalculator); 
     destructor  Destroy; override;
    procedure Cancel;
    property TokenType : TSBPublicKeyComputationTokenType read FTokenType;
    property Finished : boolean read GetFinished;
    property Data :  pointer  read FData write FData;
  end;

  TElPublicKeyAsyncCalculator =  class(TSBControlBase)
   private 
    FThreads : TElList;
    FCS :  TCriticalSection ;
    {$ifndef SB_NO_THREADPRIORITY}
    FPriority :  TThreadPriority ;
     {$endif}
    procedure KillThreads;
    procedure AddTokenToList(Token : TElPublicKeyComputationToken);
    procedure RemoveTokenFromList(Token : TElPublicKeyComputationToken);
    procedure Release(Token : TElPublicKeyComputationToken);
  public
    constructor Create( AOwner: TComponent );  override; 
     destructor  Destroy; override;
    // elgamal encryption
    function BeginElgamalEncryption(P, G, Y : PLInt) : TElPublicKeyComputationToken;
    procedure EndElgamalEncryption(Token : TElPublicKeyComputationToken;
      Src : PLInt; A, B : PLInt);
    // elgamal signing
    function BeginElgamalSigning(P, G : PLInt) : TElPublicKeyComputationToken;
    procedure EndElgamalSigning(Token : TElPublicKeyComputationToken;
      X, Src : PLInt; A, B : PLInt);
    // prime generation
    function BeginPrimeGeneration(Bits : integer) : TElPublicKeyComputationToken;
    procedure EndPrimeGeneration(Token : TElPublicKeyComputationToken;
      Prime : PLInt);
    // dsa signing
    function BeginDSASigning(P, Q, G : PLInt) : TElPublicKeyComputationToken;
    procedure EndDSASigning(Token : TElPublicKeyComputationToken; X : PLInt;
      Hash : pointer; HashSize : integer; R, S : PLInt);
    // rsa generation
    function BeginRSAGeneration(Bits : integer) : TElPublicKeyComputationToken;
    procedure EndRSAGeneration(Token : TElPublicKeyComputationToken; M, PrivE,
      PubE, Prime1, Prime2, Exp1, Exp2, Coeff : PLInt);  overload; 
    function EndRSAGeneration(Token : TElPublicKeyComputationToken;
      Blob : pointer; var BlobSize : integer): boolean; overload;
    // dsa generation
    function BeginDSAGeneration(Bits : integer) : TElPublicKeyComputationToken;
    procedure EndDSAGeneration(Token : TElPublicKeyComputationToken; P, Q, G,
      X, Y : PLInt);  overload; 
    function EndDSAGeneration(Token : TElPublicKeyComputationToken; Blob : pointer;
      var BlobSize : integer): boolean; overload;
    // elgamal generation
    function BeginElgamalGeneration(Bits : integer) : TElPublicKeyComputationToken;
    procedure EndElgamalGeneration(Token : TElPublicKeyComputationToken;
      P, G, X, Y : PLInt);
    {$ifdef SB_WINDOWS}
    {$ifndef SB_NO_THREADPRIORITY} 
    property Priority :  TThreadPriority  read FPriority write FPriority;
     {$endif}
     {$endif}
  end;

  EElPublicKeyAsyncCalculatorError = class(ESecureBlackboxError);

function GetGlobalAsyncCalculator : TElPublicKeyAsyncCalculator; 

 {$endif}

implementation

{$ifndef SB_NO_PKIASYNC}

uses
  SBRandom;

type
  TElPublicKeyComputationThread = class( TThread )
   private 
    FOwner : TElPublicKeyComputationToken;
    FElgG : PLInt;
    FElgY : PLInt;
    FBits : integer;
    FFinished : boolean;
    procedure ElgamalEncrypt;
    procedure ElgamalSign;
    procedure PrimeGeneration;
    procedure DSASign;
    procedure RSAGeneration;
    procedure DSAGeneration;
    procedure ElgamalGeneration;
    function ProgressHandler(Data:  pointer ): boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(Owner: TElPublicKeyComputationToken);  reintroduce;   overload;  
    constructor Create(CreateSuspended: boolean);  overload;      destructor  Destroy;  override; 
  end;

resourcestring
  SNotAnElgamalSigningToken = 'Not an Elgamal signing token';
  SNotADSASigningToken = 'Not a DSA signing token';
  SNotAPrimeGenerationToken = 'Not a prime generation token';
  SNotAnElgamalEncryptionToken = 'Not an Elgamal encryption token';
  //SInvalidDSAHashSize = 'Invalid DSA hash size';
  SNotAnRSAGenerationToken = 'Not an RSA generation token';
  SNotADSAGenerationToken = 'Not a DSA generation token';
  SNotAnElgamalGenerationToken = 'Not an Elgamal generation token';
  SRSAGenerationFailed = 'RSA generation failed';
  SRSAPrivateKeyDecodingFailed = 'RSA private key decoding failed';
  SDSAGenerationFailed = 'DSA generation failed';
  SElgamalGenerationFailed = 'Elgamal generation failed';
  SComputationCanceled = 'Public key computation canceled';

////////////////////////////////////////////////////////////////////////////////
// TElPublicKeyComputationThread class

constructor TElPublicKeyComputationThread.Create(CreateSuspended: boolean);
begin
  inherited Create(CreateSuspended);
  FOwner := nil;
  LCreate(FElgG);
  LCreate(FElgY);
  FFinished := false;
end;

constructor TElPublicKeyComputationThread.Create(Owner: TElPublicKeyComputationToken);
begin
  inherited Create(true);
  FOwner := Owner;
  LCreate(FElgG);
  LCreate(FElgY);
  FFinished := false;
end;

 destructor  TElPublicKeyComputationThread.Destroy;
begin
  LDestroy(FElgG);
  LDestroy(FElgY);
  inherited;
end;


procedure TElPublicKeyComputationThread.Execute;
begin
  try
    case FOwner.FTokenType of
      ttElgamalEncrypt : ElgamalEncrypt;
      ttElgamalSign : ElgamalSign;
      ttPrimeGeneration : PrimeGeneration;
      ttDSASign : DSASign;
      ttDSAGeneration : DSAGeneration;
      ttRSAGeneration : RSAGeneration;
      ttElgamalGeneration : ElgamalGeneration;
    end;
  except
    ;
  end;
  FOwner.OnThreadTerminate(Self);
end;

function TElPublicKeyComputationThread.ProgressHandler(Data:  pointer ): boolean;
begin
  Result := not Terminated;
end;

procedure TElPublicKeyComputationThread.ElgamalEncrypt;
var
  K, T2, T3, One : PLInt;
  F : boolean;
begin
  LCreate(K);
  LCreate(T2);
  LCreate(T3);
  LCreate(One);
  try
    repeat
      LGenerate(K, FOwner.FElgP.Length);
      while LGreater(K, FOwner.FElgP) do
        LShr(K);
      K.Digits[1] := K.Digits[1] or 1;
      LSub(FOwner.FElgP, One, T2);
      LGCD(K, T2, FOwner.FElgT1, T3);
      F := (FOwner.FElgT1.Length = 1) and (FOwner.FElgT1.Digits[1] = 1);
    until F;
    try
      LMModPower(FElgG, K, FOwner.FElgP, FOwner.FElgA,  ProgressHandler , nil, true);
      LMModPower(FElgY, K, FOwner.FElgP, FOwner.FElgT1,  ProgressHandler , nil, true);
    except
      Exit;
    end;
    FFinished := true;
  finally
    LDestroy(K);
    LDestroy(T2);
    LDestroy(T3);
    LDestroy(One);
  end;
end;

procedure TElPublicKeyComputationThread.ElgamalSign;
var
  K, T1, One : PLInt;
  F : boolean;
begin
  LCreate(K);
  LCreate(T1);
  LCreate(One);
  try
    LSub(FOwner.FElgP, One, FOwner.FElgT2);
    repeat
      LGenerate(K, FOwner.FElgP.Length);
      while LGreater(K, FOwner.FElgP) do
        LShr(K);
      K.Digits[1] := K.Digits[1] or 1;
      LGCD(K, FOwner.FElgT2, T1, FOwner.FElgKInv);
      F := (T1.Length = 1) and (T1.Digits[1] = 1);
    until F;
    try
      LMModPower(FElgG, K, FOwner.FElgP, FOwner.FElgA,  ProgressHandler , Self, true);
    except
      Exit;
    end;
    FFinished := true;
  finally
    LDestroy(K);
    LDestroy(T1);
    LDestroy(One);
  end;
end;

procedure TElPublicKeyComputationThread.PrimeGeneration;
begin
  try
    LGenPrime(FOwner.FPrime, FBits shr 5, false,  ProgressHandler , nil, true);
  except
    Exit;
  end;
  FFinished := true;
end;

procedure TElPublicKeyComputationThread.DSASign;
begin
  SBRndGenerateLInt(FOwner.FDSAK, 18);
  try
    LMModPower(FElgG, FOwner.FDSAK, FOwner.FDSAP, FOwner.FDSAT1,  ProgressHandler ,
      nil, true);
  except
    Exit;
  end;
  LModEx(FOwner.FDSAT1, FOwner.FDSAQ, FOwner.FDSAR);
  FFinished := true;
end;

procedure TElPublicKeyComputationThread.RSAGeneration;
var
  BufM, BufPrivExp, BufPubExp, BufBlob, BufP, BufQ, BufExp1, BufExp2, BufCoeff : ByteArray;
  SizeM, SizePrivExp, SizePubExp, SizeBlob, SizeP, SizeQ, SizeExp1, SizeExp2, SizeCoeff : integer;
  Bytes : integer;
begin

  Bytes := FBits shr 3;
  SizeM := Bytes + 4;
  SizePrivExp := SizeM;
  SizePubExp := SizeM;
  SizeBlob := (Bytes * 4) + (Bytes shr 1 + 1) + 5 + 64;
  SetLength(BufM, SizeM);
  SetLength(BufPrivExp, SizePrivExp);
  SetLength(BufPubExp, SizePubExp);
  SetLength(BufBlob, SizeBlob);
  if not SBRSA.Generate(FBits, @BufM[0], SizeM, @BufPubExp[0], SizePubExp, @BufPrivExp[0],
    SizePrivExp, @BufBlob[0], SizeBlob,  ProgressHandler , Self) then
    raise EElPublicKeyAsyncCalculatorError.Create(SRSAGenerationFailed);
  SizeP := Bytes;
  SizeQ := Bytes;
  SizeExp1 := Bytes;
  SizeExp2 := Bytes;
  SizeCoeff := Bytes;
  SizeM := Bytes + 4;
  SizePrivExp := SizeM;
  SizePubExp := SizeM;
  SetLength(BufP, SizeP);
  SetLength(BufQ, SizeQ);
  SetLength(BufExp1, SizeExp1);
  SetLength(BufExp2, SizeExp2);
  SetLength(BufCoeff, SizeCoeff);
  if not SBRSA.DecodePrivateKey(@BufBlob[0], SizeBlob, @BufM[0], SizeM, @BufPubExp[0],
    SizePubExp, @BufPrivExp[0], SizePrivExp, @BufP[0], SizeP, @BufQ[0], SizeQ,
    @BufExp1[0], SizeExp1, @BufExp2[0], SizeExp2, @BufCoeff[0], SizeCoeff) then
    raise EElPublicKeyAsyncCalculatorError.Create(SRSAPrivateKeyDecodingFailed);
  SetLength(FOwner.FKeyBlob, SizeBlob);
  SBMove(BufBlob[0], FOwner.FKeyBlob[0], SizeBlob);
  PointerToLInt(FOwner.FRSAM,  @BufM[0] , SizeM);
  PointerToLInt(FOwner.FRSAPrivExp,  @BufPrivExp[0] , SizePrivExp);
  PointerToLInt(FOwner.FRSAPubExp,  @BufPubExp[0] , SizePubExp);
  PointerToLInt(FOwner.FRSAPrime1,  @BufP[0] , SizeP);
  PointerToLInt(FOwner.FRSAPrime2,  @BufQ[0] , SizeQ);
  PointerToLInt(FOwner.FRSAExp1,  @BufExp1[0] , SizeExp1);
  PointerToLInt(FOwner.FRSAExp2,  @BufExp2[0] , SizeExp2);
  PointerToLInt(FOwner.FRSACoeff,  @BufCoeff[0] , SizeCoeff);
  FFinished := true;

end;

procedure TElPublicKeyComputationThread.DSAGeneration;
var
  Bytes : integer;
  SizeP, SizeQ, SizeG, SizeY, SizeX, SizeBlob : integer;
  BufP, BufQ, BufG, BufY, BufX, BufBlob : ByteArray;
begin

  Bytes := FBits shr 3;
  SizeP := Bytes + 4;
  SizeQ := 20;
  SizeG := SizeP;
  SizeY := SizeP;
  SizeX := SizeP;
  SizeBlob := SizeP * 4 + 85;
  SetLength(BufP, SizeP);
  SetLength(BufQ, SizeQ);
  SetLength(BufG, SizeG);
  SetLength(BufY, SizeY);
  SetLength(BufX, SizeX);
  SetLength(BufBlob, SizeBlob);
  if not SBDSA.Generate(FBits, @BufP[0], SizeP, @BufQ[0], SizeQ, @BufG[0], SizeG,
    @BufY[0], SizeY, @BufX[0], SizeX, @BufBlob[0], SizeBlob,  ProgressHandler , Self) then
    raise EElPublicKeyAsyncCalculatorError.Create(SDSAGenerationFailed);
  PointerToLInt(FOwner.FDSAP,  @BufP[0] , SizeP);
  PointerToLInt(FOwner.FDSAQ,  @BufQ[0] , SizeQ);
  PointerToLInt(FOwner.FDSAG,  @BufG[0] , SizeG);
  PointerToLInt(FOwner.FDSAX,  @BufX[0] , SizeX);
  PointerToLInt(FOwner.FDSAY,  @BufY[0] , SizeY);
  SetLength(FOwner.FKeyBlob, SizeBlob);
  SBMove(BufBlob[0], FOwner.FKeyBlob[0], SizeBlob);
  FFinished := true;

end;

procedure TElPublicKeyComputationThread.ElgamalGeneration;
begin
  if not SBElgamal.Generate(FBits, FOwner.FElgP, FOwner.FElgT1, FOwner.FElgT2, FOwner.FElgT3,
     ProgressHandler , Self) then
    raise EElPublicKeyAsyncCalculatorError.Create(SElgamalGenerationFailed);
  FFinished := true;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPublicKeyComputationToken class

constructor TElPublicKeyComputationToken.Create(TokenType : TSBPublicKeyComputationTokenType;
  Owner : TElPublicKeyAsyncCalculator);
var
  I : integer;
begin
  inherited Create;
  FThread := TElPublicKeyComputationThread.Create(Self);
  FThread.FreeOnTerminate := true;
  FTokenType := TokenType;
  FOwner := Owner;
  FOwner.AddTokenToList(Self);
  for I := Low(FLIntArray) to High(FLIntArray) do
    LCreate(FLIntArray[I]);
  // elgamal references
  FElgA := FLIntArray[0];
  FElgP := FLIntArray[1];
  FElgQ := FLIntArray[2];
  FElgR := FLIntArray[3];
  FElgT1 := FLIntArray[4];
  FElgT2 := FLIntArray[5];
  FElgT3 := FLIntArray[6];
  FElgKInv := FLIntArray[7];
  // prime
  FPrime := FLIntArray[0];
  // rsa references
  FRSAM := FLIntArray[0];
  FRSAPrivExp := FLIntArray[1];
  FRSAPubExp := FLIntArray[2];
  FRSAPrime1 := FLIntArray[3];
  FRSAPrime2 := FLIntArray[4];
  FRSAExp1 := FLIntArray[5];
  FRSAExp2 := FLIntArray[6];
  FRSACoeff := FLIntArray[7];
  // dsa references
  FDSAP := FLIntArray[0];
  FDSAQ := FLIntArray[1];
  FDSAG := FLIntArray[2];
  FDSAY := FLIntArray[3];
  FDSAX := FLIntArray[4];
  FDSAT1 := FLIntArray[5];
  FDSAR := FLIntArray[6];
  FDSAK := FLIntArray[7];
end;

 destructor  TElPublicKeyComputationToken.Destroy;
var
  I : integer;
begin
  if Assigned(FThread) then
  begin
    Stop;
    while FThread <> nil do
        Sleep(100);
  end;
  FOwner.Release(Self);
  for I := Low(FLIntArray) to High(FLIntArray) do
    LDestroy(FLIntArray[I]);
  inherited;
end;

procedure TElPublicKeyComputationToken.BeginElgamalEncryption(P, G, Y : PLInt);
begin
  LCopy(FElgP, P);
  LCopy(TElPublicKeyComputationThread(FThread).FElgG, G);
  LCopy(TElPublicKeyComputationThread(FThread).FElgY, Y);
end;

procedure TElPublicKeyComputationToken.BeginElgamalSigning(P, G : PLInt);
begin
  LCopy(FElgP, P);
  LCopy(TElPublicKeyComputationThread(FThread).FElgG, G);
end;

procedure TElPublicKeyComputationToken.BeginPrimeGeneration(Bits : integer);
begin
  TElPublicKeyComputationThread(FThread).FBits := Bits;
end;

procedure TElPublicKeyComputationToken.BeginDSASigning(P, Q, G : PLInt);
begin
  LCopy(FDSAP, P);
  LCopy(FDSAQ, Q);
  LCopy(TElPublicKeyComputationThread(FThread).FElgG, G);
end;

procedure TElPublicKeyComputationToken.BeginRSAGeneration(Bits : integer);
begin
  TElPublicKeyComputationThread(FThread).FBits := Bits;
end;

procedure TElPublicKeyComputationToken.BeginDSAGeneration(Bits : integer);
begin
  TElPublicKeyComputationThread(FThread).FBits := Bits;
end;

procedure TElPublicKeyComputationToken.BeginElgamalGeneration(Bits : integer);
begin
  TElPublicKeyComputationThread(FThread).FBits := Bits;
end;

procedure TElPublicKeyComputationToken.Start;
begin
  if Assigned(FThread) then
  begin
    {$ifdef SB_WINDOWS}
    {$ifndef SB_NO_THREADPRIORITY}
    FThread.Priority := FOwner.Priority;
     {$endif}
   {$endif}
    FThread.Resume;
  end;
end;

procedure TElPublicKeyComputationToken.Resume;
begin
  if Assigned(FThread) then
  begin
    {$ifdef SB_WINDOWS}
    {$ifndef SB_NO_THREADPRIORITY}
    FThread.Priority := FOwner.Priority;
     {$endif}
     {$endif}
    FThread.Resume;
  end;
end;

procedure TElPublicKeyComputationToken.Stop;
begin
  if Assigned(FThread) then
    FThread.Terminate;
end;

procedure TElPublicKeyComputationToken. Wait ;
begin
  while FThread <> nil do
      Sleep(50);
end;

procedure TElPublicKeyComputationToken.OnThreadTerminate(Sender: TObject);
begin
  FThreadFinished := TElPublicKeyComputationThread(Sender).FFinished;
  FThread := nil;
end;

function TElPublicKeyComputationToken.GetFinished : boolean;
begin
  Result := FThread = nil;
end;

procedure TElPublicKeyComputationToken.Cancel;
begin
  if Assigned(FThread) then
  begin
    FThread.Terminate;
    Wait;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPublicKeyAsyncCalculator class

constructor TElPublicKeyAsyncCalculator.Create;
begin
  inherited;
  FThreads := TElList.Create;
  FCS := TCriticalSection.Create;
  {$ifdef SB_WINDOWS}
  {$ifndef SB_NO_THREADPRIORITY}
  FPriority :=  tpNormal ;
   {$endif}
   {$endif}
end;

 destructor  TElPublicKeyAsyncCalculator.Destroy;
begin
  KillThreads;
  FreeAndNil(FThreads);
  FreeAndNil(FCS);
  inherited;
end;

procedure TElPublicKeyAsyncCalculator.Release(Token : TElPublicKeyComputationToken);
begin
  if not Token.Finished then
  begin
    Token.FThread.Terminate;
    Token.Wait;
  end;
  RemoveTokenFromList(Token);
end;

procedure TElPublicKeyAsyncCalculator.AddTokenToList(Token : TElPublicKeyComputationToken);
begin
  FCS.Acquire;
  try
    FThreads.Add(Token);
  finally
    FCS.Release;
  end;
end;

procedure TElPublicKeyAsyncCalculator.RemoveTokenFromList(Token : TElPublicKeyComputationToken);
begin
  FCS.Acquire;
  try
    FThreads.Remove(Token);
  finally
    FCS.Release;
  end;
end;

procedure TElPublicKeyAsyncCalculator.KillThreads;
var
  I : integer;
begin
  FCS.Acquire;
  try
    for I := 0 to FThreads.Count - 1 do
      TElPublicKeyComputationToken(FThreads[I]). Free ;
    FThreads.Clear;
  finally
    FCS.Release;
  end;
end;

function TElPublicKeyAsyncCalculator.BeginElgamalEncryption(P, G, Y : PLInt) : TElPublicKeyComputationToken;
begin
  Result := TElPublicKeyComputationToken.Create(ttElgamalEncrypt, Self);
  Result.BeginElgamalEncryption(P, G, Y);
  Result.Resume;
end;

procedure TElPublicKeyAsyncCalculator.EndElgamalEncryption(Token : TElPublicKeyComputationToken;
  Src : PLInt; A, B : PLInt);
var
  Tmp : PLInt;
begin
  if Token.TokenType <> ttElgamalEncrypt then
    raise EElPublicKeyAsyncCalculatorError.Create(SNotAnElgamalEncryptionToken);
  while (Token.FThread <> nil) do
      Sleep(50);
  if not Token.FThreadFinished then
    raise EElPublicKeyAsyncCalculatorError.Create(SComputationCanceled);
  LCopy(A, Token.FElgA);
  LCreate(Tmp);
  try
    LMult(Token.FElgT1, Src, Tmp);
    LModEx(Tmp, Token.FElgP, B);
  finally
    LDestroy(Tmp);
  end;
end;

function TElPublicKeyAsyncCalculator.BeginElgamalSigning(P, G : PLInt) : TElPublicKeyComputationToken;
begin
  Result := TElPublicKeyComputationToken.Create(ttElgamalSign, Self);
  Result.BeginElgamalSigning(P, G);
  Result.Resume;
end;

procedure TElPublicKeyAsyncCalculator.EndElgamalSigning(Token : TElPublicKeyComputationToken;
  X, Src : PLInt; A, B : PLInt);
var
  Tmp : PLInt;
begin
  if Token.TokenType <> ttElgamalSign then
    raise EElPublicKeyAsyncCalculatorError.Create(SNotAnElgamalSigningToken);
  while (Token.FThread <> nil) do
      Sleep(50);
  if not Token.FThreadFinished then
    raise EElPublicKeyAsyncCalculatorError.Create(SComputationCanceled);
  LCreate(Tmp);
  try
    LMult(Token.FElgA, X, Tmp);
    LModEx(Tmp, Token.FElgT2, Token.FElgT3);
    LCopy(A, Token.FElgA);
    if not LGreater(Src, Token.FElgT3) then
      LAdd(Src, Token.FElgT2, Tmp)
    else
      LCopy(Tmp, Src);
    LSub(Tmp, Token.FElgT3, B);
    LMult(B, Token.FElgKInv, Tmp);
    LModEx(Tmp, Token.FElgT2, B);
  finally
    LDestroy(Tmp);
  end;
end;

function TElPublicKeyAsyncCalculator.BeginPrimeGeneration(Bits : integer) : TElPublicKeyComputationToken;
begin
  Result := TElPublicKeyComputationToken.Create(ttPrimeGeneration, Self);
  Result.BeginPrimeGeneration(Bits);
  Result.Resume;
end;

procedure TElPublicKeyAsyncCalculator.EndPrimeGeneration(Token : TElPublicKeyComputationToken;
  Prime : PLInt);
begin
  if Token.TokenType <> ttPrimeGeneration then
    raise EElPublicKeyAsyncCalculatorError.Create(SNotAPrimeGenerationToken);
  while (Token.FThread <> nil) do
      Sleep(50);
  if not Token.FThreadFinished then
    raise EElPublicKeyAsyncCalculatorError.Create(SComputationCanceled);
  LCopy(Prime, Token.FPrime);
end;

function TElPublicKeyAsyncCalculator.BeginDSASigning(P, Q, G : PLInt) : TElPublicKeyComputationToken;
begin
  Result := TElPublicKeyComputationToken.Create(ttDSASign, Self);
  Result.BeginDSASigning(P, Q, G);
  Result.Resume;
end;

procedure TElPublicKeyAsyncCalculator.EndDSASigning(Token : TElPublicKeyComputationToken;
  X : PLInt; Hash : pointer; HashSize : integer; R, S : PLInt);
var
  ASign, EncSign : PLInt;
begin
  if Token.TokenType <> ttDSASign then
    raise EElPublicKeyAsyncCalculatorError.Create(SNotADSASigningToken);
  while (Token.FThread <> nil) do
      Sleep(50);
  if not Token.FThreadFinished then
    raise EElPublicKeyAsyncCalculatorError.Create(SComputationCanceled);
  LCreate(ASign);
  LCreate(EncSign);
  try
    LMult(X, Token.FDSAR, Token.FDSAT1);
    PointerToLInt(ASign, Hash , HashSize );
    LAdd(Token.FDSAT1, ASign, EncSign);
    LGCD(Token.FDSAK, Token.FDSAQ, Token.FDSAT1, ASign);
    LMult(ASign, EncSign, Token.FDSAT1);
    LModEx(Token.FDSAT1, Token.FDSAQ, S);
    LCopy(R, Token.FDSAR);
  finally
    LDestroy(ASign);
    LDestroy(EncSign);
  end;
end;

function TElPublicKeyAsyncCalculator.BeginRSAGeneration(Bits : integer) : TElPublicKeyComputationToken;
begin
  Result := TElPublicKeyComputationToken.Create(ttRSAGeneration, Self);
  Result.BeginRSAGeneration(Bits);
  Result.Resume;
end;

procedure TElPublicKeyAsyncCalculator.EndRSAGeneration(Token : TElPublicKeyComputationToken;
  M, PrivE, PubE, Prime1, Prime2, Exp1, Exp2, Coeff : PLInt);
begin
  if Token.TokenType <> ttRSAGeneration then
    raise EElPublicKeyAsyncCalculatorError.Create(SNotAnRSAGenerationToken);
  while (Token.FThread <> nil) do                 
      Sleep(50);
  if not Token.FThreadFinished then
    raise EElPublicKeyAsyncCalculatorError.Create(SComputationCanceled);
  LCopy(M, Token.FRSAM);
  LCopy(PrivE, Token.FRSAPrivExp);
  LCopy(PubE, Token.FRSAPubExp);
  LCopy(Prime1, Token.FRSAPrime1);
  LCopy(Prime2, Token.FRSAPrime2);
  LCopy(Exp1, Token.FRSAExp1);
  LCopy(Exp2, Token.FRSAExp2);
  LCopy(Coeff, Token.FRSACoeff);
end;

function TElPublicKeyAsyncCalculator.EndRSAGeneration(Token : TElPublicKeyComputationToken;
  Blob : pointer; var BlobSize : integer): boolean;
begin
  if Token.TokenType <> ttRSAGeneration then
    raise EElPublicKeyAsyncCalculatorError.Create(SNotAnRSAGenerationToken);
  while (Token.FThread <> nil) do                 
      Sleep(50);
  if not Token.FThreadFinished then
    raise EElPublicKeyAsyncCalculatorError.Create(SComputationCanceled);
  if BlobSize < Length(Token.FKeyBlob) then
  begin
    Result := false;
    BlobSize := Length(Token.FKeyBlob);
  end
  else
  begin
    Result := true;
    BlobSize := Length(Token.FKeyBlob);
    SBMove(Token.FKeyBlob[0], Blob^, BlobSize);
  end;                                      
end;

function TElPublicKeyAsyncCalculator.BeginDSAGeneration(Bits : integer) : TElPublicKeyComputationToken;
begin
  Result := TElPublicKeyComputationToken.Create(ttDSAGeneration, Self);
  Result.BeginDSAGeneration(Bits);
  Result.Resume;
end;

procedure TElPublicKeyAsyncCalculator.EndDSAGeneration(Token : TElPublicKeyComputationToken;
  P, Q, G, X, Y : PLInt);
begin
  if Token.TokenType <> ttDSAGeneration then
    raise EElPublicKeyAsyncCalculatorError.Create(SNotADSAGenerationToken);
  while (Token.FThread <> nil) do
      Sleep(50);
  if not Token.FThreadFinished then
    raise EElPublicKeyAsyncCalculatorError.Create(SComputationCanceled);
  LCopy(P, Token.FDSAP);
  LCopy(Q, Token.FDSAQ);
  LCopy(G, Token.FDSAG);
  LCopy(Y, Token.FDSAY);
  LCopy(X, Token.FDSAX);
end;

function TElPublicKeyAsyncCalculator.EndDSAGeneration(Token : TElPublicKeyComputationToken;
  Blob : pointer; var BlobSize : integer): boolean;
begin
  if Token.TokenType <> ttDSAGeneration then
    raise EElPublicKeyAsyncCalculatorError.Create(SNotADSAGenerationToken);
  while (Token.FThread <> nil) do                 
      Sleep(50);
  if not Token.FThreadFinished then
    raise EElPublicKeyAsyncCalculatorError.Create(SComputationCanceled);
  if BlobSize < Length(Token.FKeyBlob) then
  begin
    Result := false;
    BlobSize := Length(Token.FKeyBlob);
  end
  else
  begin
    Result := true;
    BlobSize := Length(Token.FKeyBlob);
    SBMove(Token.FKeyBlob[0], Blob^, BlobSize);
  end;                                      
end;

function TElPublicKeyAsyncCalculator.BeginElgamalGeneration(Bits : integer) : TElPublicKeyComputationToken;
begin
  Result := TElPublicKeyComputationToken.Create(ttElgamalGeneration, Self);
  Result.BeginElgamalGeneration(Bits);
  Result.Resume;
end;

procedure TElPublicKeyAsyncCalculator.EndElgamalGeneration(Token : TElPublicKeyComputationToken;
  P, G, X, Y : PLInt);
begin
  if Token.TokenType <> ttElgamalGeneration then
    raise EElPublicKeyAsyncCalculatorError.Create(SNotAnElgamalGenerationToken);
  while (Token.FThread <> nil) do                 
      Sleep(50);
  if not Token.FThreadFinished then
    raise EElPublicKeyAsyncCalculatorError.Create(SComputationCanceled);
  LCopy(P, Token.FElgP);
  LCopy(G, Token.FElgT1);
  LCopy(X, Token.FElgT2);
  LCopy(Y, Token.FElgT3);
end;

////////////////////////////////////////////////////////////////////////////////
// Factory retrieving function

var
  GlobalAsyncCalc : TElPublicKeyAsyncCalculator  =  nil;

function GetGlobalAsyncCalculator : TElPublicKeyAsyncCalculator;
begin
  if GlobalAsyncCalc = nil then
    GlobalAsyncCalc := TElPublicKeyAsyncCalculator.Create( nil );
  Result := GlobalAsyncCalc;
  RegisterGlobalObject(GlobalAsyncCalc);
end;

 {$endif SB_NO_PKIASYNC}

end.
