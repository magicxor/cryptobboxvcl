
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSharedResource;

interface

uses 
  SysUtils,
  {$ifdef SB_WINDOWS}
  Windows,
   {$else}
  SyncObjs,
   {$endif}
  SBUtils,
  SBTypes,
  SBRandom,
  SBConstants;



{$ifndef SB_WINDOWS}
type
  TElSemaphore = class
  protected
    FCS : {$ifdef FPC}TRTLCriticalSection {$else}TCriticalSection {$endif};
    FEvent : TEvent;
    FCount : integer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Wait;
    procedure Release(Count : integer);
    property Count : integer read FCount;
  end;
 {$endif}

type
  TElSharedResource = class
  private
    {$ifndef SB_VCL_USE_MRXWS}
    FActiveThreadID: Cardinal;
    FActive : integer;
    FWaitingReaders : integer;
    FWaitingWriters : integer;
    FSemReaders,
    FSemWriters : {$ifdef SB_WINDOWS}THandle {$else}TElSemaphore {$endif};
    {$ifndef FPC}
    FCS : {$ifdef SB_WINDOWS}_RTL_CRITICAL_SECTION {$else}TCriticalSection {$endif};
     {$else}
    FCS : TRTLCriticalSection;
     {$endif}
    FWriteDepth : integer;
     {$else}
    FAction : integer;
    FSynchronizer : TMultiReadExclusiveWriteSynchronizer;
     {$endif}
    FEnabled : boolean;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure WaitToRead;
    procedure WaitToWrite;
    procedure Done;
    property Enabled : boolean read FEnabled write FEnabled  default true ;
  end;

implementation


{$ifndef SB_VCL_USE_MRXWS}

{$ifndef SB_WINDOWS}
constructor TElSemaphore.Create;
{$ifdef SB_USE_NAMED_EVENTS}
var
  EventName : string;
  Buf : ByteArray;
  I : integer;
 {$endif}
begin
  inherited;
  {$ifdef FPC}
  InitCriticalSection(FCS);
   {$else}
  FCS := TCriticalSection.Create;
   {$endif}
  {$ifdef SB_USE_NAMED_EVENTS}
  EventName := 'TElSemaphore_';
  SetLength(Buf, 8);
  SBRndGenerate(@Buf[0], Length(Buf));
  for I := 0 to Length(Buf) - 1 do
    EventName := EventName + IntToHex(Buf[I], 2);
  FEvent := TEvent.Create(nil, true, false, EventName);
   {$else}
  FEvent := TEvent.Create(nil, true, false, '');
   {$endif}
  FCount := 0;
end;

destructor TElSemaphore.Destroy;
begin
  FreeAndNil(FEvent);
  {$ifdef FPC}
  DoneCriticalSection(FCS);
   {$else}
  FreeAndNil(FCS);
   {$endif}
  inherited;
end;

procedure TElSemaphore.Wait;
begin
  while true do
  begin
    // While any number of threads may be waiting to proceed, we can
    // only allow a maximum of Count threads to go further. If Count is
    // zero when current thread enters the critical section, the thread is
    // re-sent back to WaitFor to wait for next available moment.
    FEvent.WaitFor(INFINITE);
    {$ifdef FPC}
    EnterCriticalSection(FCS);
     {$else}
    FCS.Acquire;
     {$endif}
    try
      if FCount > 0 then
      begin
        Dec(FCount);
        if FCount = 0 then
          FEvent.ResetEvent();
        Exit;
      end
    finally
      {$ifdef FPC}
      LeaveCriticalSection(FCS);
       {$else}
      FCS.Release;
       {$endif}
    end;
  end;
end;

procedure TElSemaphore.Release(Count : integer);
begin
  {$ifdef FPC}
  EnterCriticalSection(FCS);
   {$else}
  FCS.Acquire;
   {$endif}
  try
    Inc(FCount, Count);
    if FCount > 0 then
      FEvent.SetEvent;
  finally
    {$ifdef FPC}
    LeaveCriticalSection(FCS);
     {$else}
    FCS.Release;
     {$endif}
  end;
end;
 {$endif}

{$ifndef SB_WINDOWS}
{$ifndef FPC}
procedure EnterCriticalSection(CS : TCriticalSection);
begin
  CS.Acquire;
end;

procedure LeaveCriticalSection(CS : TCriticalSection);
begin
  CS.Release;
end;
 {$endif}
 {$endif}

constructor TElSharedResource.Create;
begin
  FWaitingReaders := 0;
  FWaitingWriters := 0;
  {$ifdef SB_WINDOWS} 
  FSemReaders := CreateSemaphore(nil, 0, MAXINT, nil);
  FSemWriters := CreateSemaphore(nil, 0, MAXINT, nil);
  InitializeCriticalSection(FCS);
   {$else}
  FSemReaders := TElSemaphore.Create();
  FSemWriters := TElSemaphore.Create();
  {$ifdef FPC}
  InitCriticalSection(FCS);
   {$else}
  FCS := TCriticalSection.Create;
   {$endif}
   {$endif}
  FActiveThreadID := 0;
  FWriteDepth := 0;
  FEnabled := true;
end;

destructor TElSharedResource.Destroy;
begin
  FWaitingReaders := 0;
  FWaitingWriters := 0;
  FActive := 0;
  {$ifdef SB_WINDOWS}
  DeleteCriticalSection(FCS);
  CloseHandle(FSemReaders);
  CloseHandle(FSemWriters);
   {$else}
  {$ifdef FPC}
  DoneCriticalSection(FCS);
   {$else}
  FreeAndNil(FCS);
   {$endif}
  FreeAndNil(FSemReaders);
  FreeAndNil(FSemWriters);
   {$endif}
  inherited;
end;

procedure TElSharedResource.WaitToRead;
var
  ResourceWritePending : boolean;
  DoWait : boolean;
begin
  if not Enabled then Exit;
  EnterCriticalSection(FCS);
  ResourceWritePending := (FWaitingWriters <> 0) or (FActive < 0);
  if ResourceWritePending and (FActiveThreadID <> 0) and (FActiveThreadID <> GetCurrentThreadID) then
  begin
    DoWait := true;
    Inc(FWaitingReaders);
  end
  else
  begin
    DoWait := false;
    FActiveThreadID := GetCurrentThreadID;
    if FActive = -1 then // our thread already writes to the resource
      Inc(FWriteDepth) // increasing usage depth
    else
      Inc(FActive);
  end;
  LeaveCriticalSection(FCS);
  if DoWait then
    {$ifdef SB_WINDOWS}
    WaitForSingleObject(FSemReaders, INFINITE);
     {$else}
    FSemReaders.Wait;
     {$endif}
end;

procedure TElSharedResource.WaitToWrite;
var
  ResourceOwned : boolean;
  DoWait : boolean;
begin
  if not Enabled then Exit;
  EnterCriticalSection(FCS);
  ResourceOwned := FActive <> 0;
  if ResourceOwned {and (FActiveThreadID <> 0) and (FActiveThreadID <> GetCurrentThreadID)} then
  begin
    if FActiveThreadID = GetCurrentThreadID then
    begin
      Inc(FWriteDepth);
      DoWait := false;
    end
    else
    begin
      DoWait := true;
      Inc(FWaitingWriters);
    end;
  end
  else
  begin
    DoWait := false;
    FActiveThreadID := GetCurrentThreadID;
    //Dec(FActive)
    FActive := -1;
    FWriteDepth := 1;
  end;
  LeaveCriticalSection(FCS);
  if DoWait then
  begin
    {$ifdef SB_WINDOWS}
    WaitForSingleObject(FSemWriters, cardinal(INFINITE));
     {$else}
    FSemWriters.Wait;
     {$endif}
    FActiveThreadID := GetCurrentThreadID;
  end;
end;

procedure TElSharedResource.Done;
var
  Sem : {$ifdef SB_WINDOWS}THandle {$else}TElSemaphore {$endif};
  Count : longint;
begin
  if not Enabled then Exit;
  EnterCriticalSection(FCS);
  if FActive > 0 then
    Dec(FActive)
  else
  begin
    Dec(FWriteDepth);
    if (FWriteDepth = 0) then
      Inc(FActive);
  end;
  Sem := {$ifdef SB_WINDOWS}0 {$else}nil {$endif};
  Count := 1;
  if FActive = 0 then
  begin
    FActiveThreadID := 0;
    if FWaitingWriters > 0 then
    begin
      FActive := -1;
      FWriteDepth := 1;
      Dec(FWaitingWriters);
      Sem := FSemWriters;
    end
    else if FWaitingReaders > 0 then
    begin
      FActive := FWaitingReaders;
      FWaitingReaders := 0;
      Sem := FSemReaders;
      Count := FActive;
    end;
  end;
  LeaveCriticalSection(FCS);
  if Sem <> {$ifdef SB_WINDOWS}0 {$else}nil {$endif} then
    {$ifdef SB_WINDOWS}
    ReleaseSemaphore(Sem, Count, nil);
     {$else}
    Sem.Release(Count);
     {$endif}
end;

 {$else}

constructor TElSharedResource.Create;
begin
  inherited;
  FSynchronizer := TMultiReadExclusiveWriteSynchronizer.Create;
  FEnabled := true;
end;

destructor TElSharedResource.Destroy;
begin
  FSynchronizer.Free;
  inherited;
end;

procedure TElSharedResource.WaitToRead;
begin
  if not Enabled then Exit;
  FSynchronizer.BeginRead;
  FAction := 1;
end;

procedure TElSharedResource.WaitToWrite;
begin
  if not Enabled then Exit;
  FSynchronizer.BeginWrite;
  FAction := 2;
end;

procedure TElSharedResource.Done;
begin
  if not Enabled then Exit;
  if FAction = 1 then
    FSynchronizer.EndRead
  else
  if FAction = 2 then
    FSynchronizer.EndWrite;
end;

 {$endif}

end.
