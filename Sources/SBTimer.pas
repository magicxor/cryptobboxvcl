(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBTimer;

interface

uses
  {$ifdef SB_WINDOWS}
  Windows,
   {$else}
  SyncObjs,
   {$endif}
  Classes,
  SysUtils,
  SBSharedResource,
  SBTypes,
  SBUtils;

  {$undef STEP_TIMER}
  {$ifdef CLX_USED}
    {$define STEP_TIMER}
   {$endif}
  {$ifdef NET_CF_1_0}
    {$define STEP_TIMER}
   {$endif}

type

  TTimerThread = class  (TThread) 
  private
    {$ifdef SB_WINDOWS}
    FEvent : THandle;
     {$else}
    FEvent : TEvent;
     {$endif}
    {$ifdef STEP_TIMER}
    FTimerStep : integer;
    FCounter : Int64;
     {$endif}
    FOnTimer : TNotifyEvent;
    FOnFinish : TNotifyEvent;
    FInterval: Integer;
    FTerminate : boolean;
    FEnabled : boolean;
  protected
    procedure DoTimer;
    procedure SetInterval(Interval: Integer);
    procedure SetEnabled(Value: boolean);
    function GetEnabled : boolean;
  public
    constructor Create;
     destructor  Destroy; override;

    procedure Execute;  override; 

    property OnTimer : TNotifyEvent read FOnTimer write FOnTimer;
    property OnFinish : TNotifyEvent read FOnFinish write FOnFinish;
    
    property Interval: Integer read FInterval write SetInterval;
    {$ifdef STEP_TIMER}
    property TimerStep: Integer read FTimerStep write FTimerStep;
     {$endif}
    property TerminateNow : boolean read FTerminate write FTerminate;
    property Enabled : boolean read GetEnabled write SetEnabled;
  end;
  

  TElTimer = class(TSBControlBase)
  protected
    FOnTimer : TNotifyEvent;
    FInterval : integer;
    {$ifdef STEP_TIMER}
    FTimerStep : integer;
     {$endif}
    FTimerThread : TTimerThread;
    FRecreateThreads : boolean;
    FTimerThreadCS : TElSharedResource;
    procedure SetInterval(Value : integer);
    function GetEnabled : boolean;
    procedure SetEnabled(Value: boolean);
    (*
    procedure StartTimer;
    procedure StopTimer;
    *)
    procedure HandleTimerEvent(Sender: TObject);
    //procedure HandleFinishEvent(Sender: TObject);
    procedure CreateTimerIfNeeded;
    procedure KillTimer;
  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override; 
    property Interval : integer read FInterval write SetInterval;
    {$ifdef STEP_TIMER}
    property TimerStep : integer read FTimerStep write FTimerStep;
     {$endif}
    property Enabled : boolean read GetEnabled write SetEnabled;
    property RecreateThreads : boolean read FRecreateThreads write FRecreateThreads;
  published
    property OnTimer : TNotifyEvent read FOnTimer write FOnTimer;
  end;

implementation

////////////////////////////////////////////////////////////////////////////////
// TTimerThread

constructor TTimerThread.Create;
begin
  inherited Create(true);
  {$ifdef SB_WINDOWS}
  FEvent := CreateEvent(nil, false, true, nil); // no need for named event here
   {$else}
  FEvent := TEvent.Create(nil, false, {$ifdef DELPHI_MAC}false {$else}true {$endif}, '');
   {$endif}
  FInterval := 1000;
  {$ifdef STEP_TIMER}
  FCounter := 0;
  FTimerStep := 100;
   {$endif}
  FTerminate := false;
  FEnabled := false;
end;

 destructor  TTimerThread.Destroy;
begin
  FEnabled := false;
  inherited;
  {$ifdef SB_WINDOWS}
  CloseHandle(FEvent);
   {$else}
  FreeAndNil(FEvent);
   {$endif}
end;

procedure TTimerThread.SetEnabled(Value: boolean);
begin
  {$ifndef STEP_TIMER}
  if (not Value) and (FEnabled) then
  begin
    {$ifdef SB_WINDOWS}
    SetEvent(FEvent);
     {$else}
    FEvent.SetEvent();
     {$endif}
  end;

  if Value then
  begin
    {$ifdef SB_WINDOWS}
    ResetEvent(FEvent);
     {$else}
    {$ifdef FPC}
    FEvent.ResetEvent;
     {$else}
    FEvent.ResetEvent;
     {$endif}
     {$endif}
  end;
   {$endif}

  FEnabled := Value;
end;

function TTimerThread.GetEnabled : boolean;
begin
  Result := FEnabled;
end;

procedure TTimerThread.Execute;
begin
  while not TerminateNow do
  begin
    if FEnabled then
    begin
      {$ifdef STEP_TIMER}
      Sleep(FTimerStep);
      Inc(FCounter, FTimerStep);
      if FCounter > FInterval then
      begin
        if FEnabled then
          DoTimer;
        FCounter := 0;
      end;
       {$else}
      // II: uncomment Synchronize in Delphi applications if there's
      // some GUI access from the OnSend event of ElSecureClient/ElSecureServer
      if not TerminateNow then
      begin
        {$ifdef SB_WINDOWS}
        if (WaitForSingleObject(FEvent, FInterval) <> WAIT_OBJECT_0) and FEnabled then
          {Synchronize}(DoTimer);
         {$else}
        if (FEvent.WaitFor(FInterval) <> wrSignaled) and FEnabled then
          DoTimer;
         {$endif}
      end
      else
        Break;
       {$endif}
    end
    else
      Sleep(500);
  end;
  if Assigned(FOnFinish) then
    FOnFinish(Self);
end;

procedure TTimerThread.DoTimer;
begin
  if Assigned(FOnTimer) then
    FOnTimer(Self);
end;

procedure TTimerThread.SetInterval(Interval: Integer);
begin
  FInterval := Interval;
end;

////////////////////////////////////////////////////////////////////////////////
// TElTimer class

constructor TElTimer.Create( AOwner : TComponent );
begin
  inherited;
  FInterval := 1000;
  {$ifdef STEP_TIMER}
  FTimerStep := 100;
   {$endif}
  FRecreateThreads := true;
  FTimerThread := nil;
  FTimerThreadCS := TElSharedResource.Create();
  (*
  FTimerThread := TTimerThread.Create();
  FTimerThread.Enabled := false;
  {$ifdef SB_VCL}
  FTimerThread.FreeOnTerminate := true;
  FTimerThread.OnTimer := HandleTimerEvent;
  //FTimerThread.OnFinish := HandleFinishEvent;
  if FInterval <> 0 then
    FTimerThread.Interval := FInterval;
  FTimerThread.Resume;
  {$else}
  FTimerThread.FThread := System.Threading.Thread.Create({$ifndef SB_NET}FTimerThread.Execute{$else}new ThreadStart(@FTimerThread.Execute){$endif});
  FTimerThread.FThread.Priority := System.Threading.ThreadPriority.Lowest;
  if FInterval <> 0 then
    FTimerThread.Interval := FInterval;
  FTimerThread.OnTimer {$ifndef SB_NET}:={$else}+={$endif} HandleTimerEvent;
  //FTimerThread.OnFinish {$ifndef SB_NET}:={$else}+={$endif} HandleFinishEvent;
  FTimerThread.FThread.Start;
  {$endif}
  *)
end;

 destructor  TElTimer.Destroy;
begin
  if Assigned(FTimerThread) then
    KillTimer;
  FreeAndNil(FTimerThreadCS);
  inherited;
end;

procedure TElTimer.SetInterval(Value : integer);
begin
  if Value <> FInterval then
  begin
    FInterval := Value;
    FTimerThreadCS.WaitToWrite;
    try
      if Assigned(FTimerThread) then
        FTimerThread.Interval := Value;
    finally
      FTimerThreadCS.Done;
    end;
  end;
end;

function TElTimer.GetEnabled : boolean;
begin
  FTimerThreadCS.WaitToRead;
  try
    if Assigned(FTimerThread) then
      Result := FTimerThread.Enabled
    else
      Result := false;
  finally
    FTimerThreadCS.Done;
  end;
end;

procedure TElTimer.SetEnabled(Value: boolean);
begin
  if Value then
  begin
    CreateTimerIfNeeded;
    FTimerThreadCS.WaitToWrite;
    try
      FTimerThread.Enabled := true;
    finally
      FTimerThreadCS.Done;
    end;
  end
  else
  begin
    FTimerThreadCS.WaitToWrite;
    try
      if Assigned(FTimerThread) then
      begin
        FTimerThread.Enabled := false;       
        if FRecreateThreads then
          KillTimer;
      end;
    finally
      FTimerThreadCS.Done;
    end;
  end;
end;

procedure TElTimer.CreateTimerIfNeeded;
begin
  FTimerThreadCS.WaitToWrite;
  try
    if not Assigned(FTimerThread) then
    begin
      FTimerThread := TTimerThread.Create();
      FTimerThread.Enabled := false;
      {$ifdef STEP_TIMER}
      FTimerThread.TimerStep := FTimerStep;
       {$endif}
      FTimerThread.FreeOnTerminate := true;
      FTimerThread.OnTimer := HandleTimerEvent;
      if FInterval <> 0 then
        FTimerThread.Interval := FInterval;
      FTimerThread.Resume;
    end;
  finally
    FTimerThreadCS.Done;
  end;
end;

procedure TElTimer.KillTimer;
begin
  FTimerThreadCS.WaitToWrite;
  try
    if Assigned(FTimerThread) then
    begin
      FTimerThread.OnTimer := nil; // Added by EM to prevent possibility of error described in ticket #22954
      FTimerThread.TerminateNow := true;
      FTimerThread := nil;
    end;
  finally
    FTimerThreadCS.Done;
  end;
end;

(*
procedure TElTimer.StartTimer;
begin
*)
  (*
  FTimerThread := TTimerThread.Create();
  {$ifdef SB_VCL}
  FTimerThread.FreeOnTerminate := false;
  FTimerThread.OnTimer := HandleTimerEvent;
  FTimerThread.OnFinish := HandleFinishEvent;
  if FInterval <> 0 then
    FTimerThread.Interval := FInterval;
  FTimerThread.Resume;
  {$else}
  FTimerThread.FThread := System.Threading.Thread.Create({$ifndef SB_NET}FTimerThread.Execute{$else}new ThreadStart(@FTimerThread.Execute){$endif});
  FTimerThread.FThread.Priority := System.Threading.ThreadPriority.Lowest;
  if FInterval <> 0 then
    FTimerThread.Interval := FInterval;
  FTimerThread.OnTimer {$ifndef SB_NET}:={$else}+={$endif} HandleTimerEvent;
  FTimerThread.OnFinish {$ifndef SB_NET}:={$else}+={$endif} HandleFinishEvent;
  FTimerThread.FThread.Start;
  {$endif}
  *)
(*
end;
*)

(*
procedure TElTimer.StopTimer;
begin
*)
  (*
  if Assigned(FTimerThread) then
  begin
    FTimerThread.OnTimer := nil;
    FTimerThread.TerminateNow := true;
    {$ifdef SB_VCL}
    FTimerThread.Terminate;
    {$endif}
    FTimerThread := nil;
  end;
  *)
(*
end;
*)

procedure TElTimer.HandleTimerEvent(Sender: TObject);
begin
  if Assigned(FOnTimer) then
    FOnTimer(Self);
end;

(*
procedure TElTimer.HandleFinishEvent(Sender: TObject);
begin
  //FreeAndNil(Sender);
end;
*)

end.
