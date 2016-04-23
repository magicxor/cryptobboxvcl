
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$i SecBbox.inc}

unit SBIDEA;

interface

uses
  SBTypes,
  SBUtils;   

{$ifndef SB_NO_IDEA}

  
const
  TIDEAExpandedKeySize = 52 shl 1;

type
  TIDEAKey =  array[0..15] of byte;
  PIDEAKey = ^TIDEAKey;

  TIDEAExpandedKey = array[0..51] of word;
  PIDEAExpandedKey = ^TIDEAExpandedKey;

// Key expansion routines
procedure ExpandKeyForEncryption(const Key:   TIDEAKey  ; 
   out  ExpandedKey: TIDEAExpandedKey); 
procedure ExpandKeyForDecryption(const CipherKey: TIDEAExpandedKey;
   out  DecipherKey: TIDEAExpandedKey); 

// Block processing routines
procedure Encrypt(var B0, B1 : cardinal; const Key: TIDEAExpandedKey); 

 {$endif SB_NO_IDEA}

{$ifndef SB_MSSQL}
var
  IdeaEnabled : boolean  =  true;
 {$endif}

implementation

{$ifndef SB_NO_IDEA}

uses
  SysUtils;

// Internal functions

(*function Multiply(X, Y: word): word; {$ifdef SB_VCL} register;{$endif}
var
  A, B: word;
  P: longword;
begin
  P := X * Y;
  if P = 0 then
    {$ifndef SB_NET}
    Result := $10001 - X - Y
    {$else}
    Result := Word($10001 - Integer(X) - Integer(Y))
    {$endif}
  else
  begin
    {$ifndef SB_VCL}
    A := word(P shr 16);
    B := word((P shl 16) shr 16);
    {$else}
    A := LongRec(P).Hi;
    B := LongRec(P).Lo;
    {$endif}
    A := B - A;
    if B < A then
      {$ifndef SB_NET}
      Inc(A, $10001);
      {$else}
      Inc(A);
      {$endif}
    Result := A;
  end;
end; *)

function Invert(X: word): word;
var
  A, B, C, D: word;
begin
  if X <= 1 then
    Result := X
  else
  begin
    A := 1;
    B := $10001 div X;
    C := $10001 mod X;
    while C <> 1 do
    begin
      D := X div C;
      X := X mod C;
      Inc(A, B * D);
      if X = 1 then
      begin
        Result := A;
        exit;
      end;
      D := C div X;
      C := C mod X;
      Inc(B, A * D);
    end;
    Result := 1 - B;
  end;
end;

// Key expansion routines

procedure ExpandKeyForEncryption(const Key:   TIDEAKey  ;
   out  ExpandedKey: TIDEAExpandedKey);
var
  I: integer;
begin

  for I := 0 to 7 do
    ExpandedKey[I] := (Key[I shl 1] shl 8) or Key[I shl 1 + 1];
  for I := 0 to 39 do
    ExpandedKey[I + 8] := (ExpandedKey[I and not 7 + (I + 1) and 7] shl 9) or
    (ExpandedKey[I and not 7 + (I + 2) and 7] shr 7);
  for I := 41 to 44 do
    ExpandedKey[I + 7] := (ExpandedKey[I] shl 9) or (ExpandedKey[I + 1] shr 7);
end;

procedure ExpandKeyForDecryption(const CipherKey: TIDEAExpandedKey; 
     out  DecipherKey: TIDEAExpandedKey);
var
  A, B, C: Word;
  I, CI, DI: integer;
begin

  A := Invert(CipherKey[0]);
  B := 65536 - CipherKey[1];
  C := 65536 - CipherKey[2];
  DecipherKey[51] := Invert(CipherKey[3]);
  DecipherKey[50] := C;
  DecipherKey[49] := B;
  DecipherKey[48] := A;
  CI := 4;
  DI := 48;
  for I := 0 to 7 do
  begin
    Dec(DI, 6);
    A := CipherKey[CI];
    DecipherKey[DI + 5] := CipherKey[CI + 1];
    DecipherKey[DI + 4] := A;
    A := Invert(CipherKey[CI + 2]);
    B := 65536 - CipherKey[CI + 3];
    C := 65536 - CipherKey[CI + 4];
    DecipherKey[DI + 3] := Invert(CipherKey[CI + 5]);
    DecipherKey[DI + 2] := B;
    DecipherKey[DI + 1] := C;
    DecipherKey[DI] := A;
    Inc(CI, 6);
  end;
  A := DecipherKey[DI + 2];
  DecipherKey[DI + 2] := DecipherKey[DI + 1];
  DecipherKey[DI + 1] := A;
end;

// Block processing routines

procedure Encrypt(var B0, B1 : cardinal; const Key: TIDEAExpandedKey);
var
  I: integer;
  A, B, C, D, X, Y: word;
  T : cardinal;
  PKey: PWord;
begin
  A := (B0 shl 8) or ((B0 shr 8) and $ff);
  B := ((B0 shr 8) and $ff00) or (B0 shr 24);
  C := (B1 shl 8) or ((B1 shr 8) and $ff);
  D := ((B1 shr 8) and $ff00) or (B1 shr 24);
  PKey := @Key;
  for I := 0 to 7 do
  begin
    { A }
    T := A *  PKey^ ;
    if T = 0 then
      A := $10001 - integer(A) - integer( PKey^ )
    else
    begin
      T := $10001 + T and $ffff - T shr 16;
      if (T > $10000) then
        A := T - 1
      else
        A := T;
    end;
    //A := Multiply(A, PKey^);
    Inc(PKey);
    { B }
    Inc(B,  PKey^ );
    Inc(PKey);
    { C }
    Inc(C,  PKey^ );
    Inc(PKey);
    { D }
    T := D *  PKey^ ;
    if T = 0 then
      D := $10001 - integer(D) - integer( PKey^ )
    else
    begin
      T := $10001 + T and $ffff - T shr 16;
      if (T > $10000) then
        D := T - 1
      else
        D := T;
    end;
    //D := Multiply(D, PKey^);
    Inc(PKey);
    Y := C;
    T := (C xor A) *  PKey^ ;
    if T = 0 then
      C := $10001 - integer((C xor A)) - integer( PKey^ )
    else
    begin
      T := $10001 + T and $ffff - T shr 16;
      if (T > $10000) then
        C := T - 1
      else
        C := T;
    end;
    //C := Multiply(C xor A, PKey^);
    Inc(PKey);
    X := B;
    T := ((B xor D + C) and $ffff) *  PKey^ ;
    if T = 0 then
      B := $10001 - integer(((B xor D) + C)) - integer( PKey^ )
    else
    begin
      T := $10001 + T and $ffff - T shr 16;
      if (T > $10000) then
        B := T - 1
      else
        B := T;
    end;
    //B := Multiply(B xor D + C, PKey^);
    Inc(PKey);
    C := C + B;
    A := A xor B;
    D := D xor C;
    B := B xor Y;
    C := C xor X;
  end;

  T := A *  PKey^ ;
  if T = 0 then
    A := $10001 - integer( PKey^ ) - integer(A)
  else
  begin
      T := $10001 + T and $ffff - T shr 16;
      if (T > $10000) then
        A := T - 1
      else
        A := T;
  end;
  //A := Multiply(A, PKey^);
  Inc(PKey);
  Inc(C,  PKey^ );
  Inc(PKey);
  Inc(B,  PKey^ );
  Inc(PKey);

  T := D *  PKey^ ;
  if T = 0 then
    D := $10001 - integer( PKey^ ) - integer(D)
  else
  begin
    T := $10001 + T and $ffff - T shr 16;
    if (T > $10000) then
      D := T - 1
    else
      D := T;
  end;
  //D := Multiply(D, PKey^);

  B0 := (A shr 8) or ((A and $ff) shl 8) or ((C and $ff00) shl 8) or (C shl 24);
  B1 := (B shr 8) or ((B and $ff) shl 8) or ((D and $ff00) shl 8) or (D shl 24);
end;

 {$endif SB_NO_IDEA}

end.
