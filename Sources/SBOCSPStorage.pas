(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBOCSPStorage;

interface

uses
  Classes,
  SysUtils,
  {$ifdef SB_UNICODE_VCL}
   {$endif}
  SBConstants,
  SBTypes,
  SBUtils,
  SBOCSPCommon,
  SBOCSPClient,
  SBPKICommon;
  

type
  TElOCSPResponseStorage = class (TPersistent) 
  private
    FList : TElList;
    function GetResponse(Index : integer): TElOCSPResponse;
    function GetCount : integer;
  public
    constructor Create;
     destructor  Destroy; override;
    function Add(Resp : TElOCSPResponse): integer;  overload; 
    function Add(): integer;  overload; 
    procedure Remove(Index : integer);
    function IndexOf(Resp : TElOCSPResponse): integer;
    procedure Clear;
    property Responses[Index: integer]: TElOCSPResponse read GetResponse;
    property Count : integer read GetCount;
  end;

implementation

////////////////////////////////////////////////////////////////////////////////
// TElOCSPResponseStorage class

constructor TElOCSPResponseStorage.Create;
begin
  inherited;
  FList := TElList.Create;
end;

 destructor  TElOCSPResponseStorage.Destroy;
begin
  Clear;
  FreeAndNil(FList);
  inherited;
end;

function TElOCSPResponseStorage.Add(Resp : TElOCSPResponse): integer;
var
  NewResp : TElOCSPResponse;
begin
  NewResp := TElOCSPResponse.Create;
  NewResp.Assign(Resp);
  Result := FList.Add(NewResp);
end;

function TElOCSPResponseStorage.Add(): integer;
begin
  Result := FList.Add(TElOCSPResponse.Create);
end;

procedure TElOCSPResponseStorage.Remove(Index : integer);
var
  Resp : TElOCSPResponse;
begin
  Resp := TElOCSPResponse(FList[Index]);
  FList. Delete (Index);
  FreeAndNil(Resp);
end;

function TElOCSPResponseStorage.IndexOf(Resp : TElOCSPResponse): integer;
var
  I : integer;
begin
  Result := -1;
  for I := 0 to FList.Count - 1 do
    if TElOCSPResponse(FList[I]).EqualsTo(Resp) then
    begin
      Result := I;
      Break;
    end;
end;

procedure TElOCSPResponseStorage.Clear;
var
  I : integer;
  Resp : TElOCSPResponse;
begin
  try
    for I := 0 to FList.Count - 1 do
    begin
      Resp := TElOCSPResponse(FList[I]);
      FreeAndNil(Resp);
    end;
  finally
    FList.Clear;
  end;
end;

function TElOCSPResponseStorage.GetResponse(Index : integer): TElOCSPResponse;
begin
  Result := TElOCSPResponse(FList[Index]);
end;

function TElOCSPResponseStorage.GetCount : integer;
begin
  Result := FList.Count;
end;

end.
