
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSerpent;

interface

uses
  SBTypes,
  SBUtils
  ;

type

  TSerpentKey =  array of byte;
  TSerpentBuffer =  array[0..15] of byte;
  TSerpentExpandedKey = array[0..32, 0..3] of Cardinal;
  PSerpentExpandedKey = ^TSerpentExpandedKey;
  TSerpentExpandedKeyEx = array[0..131] of Cardinal;

{ Block routines }
procedure ExpandKey(const Key : TSerpentKey; var {$ifndef B_X}ExpandedKey : TSerpentExpandedKey {$else}ExpandedKeyEx : TSerpentExpandedKeyEx {$endif}); 
procedure EncryptBlock(var B0, B1, B2, B3 : cardinal; const {$ifndef B_X}ExpandedKey : TSerpentExpandedKey {$else}ExpandedKeyEx : TSerpentExpandedKeyEx {$endif}); 
procedure DecryptBlock(var B0, B1, B2, B3 : cardinal; const {$ifndef B_X}ExpandedKey : TSerpentExpandedKey {$else}ExpandedKeyEx : TSerpentExpandedKeyEx {$endif}); 

implementation
uses
  SysUtils;

type
  PLongwordArray = ^TLongwordArray;
  TLongwordArray = array[0..16383] of cardinal;
  TXorTable = array[0..127, 0..7] of byte;
  PXorTable = ^TXorTable;

const
  PHI = $9E3779B9;

procedure SBox0(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t06, t07, t09 : cardinal;
begin
  z := b xor c xor (a or d);
  t06 := a xor d;
  t07 := b or c;
  t09 := (a xor b) and t07;
  y := t09 xor (d and (c or z));
  w := not (t06 xor t07 xor (t09 and y));
  x := c xor d xor w xor (b and t06);
end;

procedure SBox0Inv(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t03, t05, t13, t14 : cardinal;
begin
  t01 := c xor d;
  t03 := b or c;
  t05 := (a or b) xor t01;
  y := not t05;
  x := (t03 and (b xor d)) xor (a or (c and t01));
  t13 := x xor (a or t05);
  t14 := t03 xor (d or y);
  z := t14 xor t13;
  w := a xor c xor (t14 or (t05 and t13));
end;

procedure SBox1(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t02, t05, t10 : cardinal;
begin
  t01 := a or d;
  t02 := c xor d;
  t05 := a or (not b);
  y := t02 xor t05;
  t10 := (t01 and t02) xor (b or (d and (a xor c)));
  z := not t10;
  x := (b and d) xor y xor t01 xor t10;
  w := c xor (t05 and (t10 or x));
end;

procedure SBox1Inv(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t03, t04, t06 : cardinal;
begin
  t01 := a xor b;
  t03 := a and c;
  t04 := c xor (b or d);
  t06 := t01 and (a or t04);
  y := not ((d or t03) xor t06);
  x := (t04 or t03) xor (d and (b xor t06));
  z := t01 xor t04;
  w := (a or y) xor c xor t06 xor x;
end;


procedure SBox2(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t02, t03, t05, t09 : cardinal;
begin
  t01 := a or c;
  t02 := a xor b;
  t03 := d xor t01;
  w := t02 xor t03;
  t05 := c xor w;
  t09 := t03 xor (b or t05);
  x := (t02 or t09) xor (t01 and (b xor t05));
  z := not t09;
  y := (a or d) xor b xor t09 xor x;
end;

procedure SBox2Inv(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t02, t06, t10 : cardinal;
begin
  t02 := c xor d;
  w := a xor d xor (b or t02);
  t06 := a or c;
  t10 := (not d) or (a and c);
  z := (b and t06) xor t10;
  x := (t06 and t02) xor (b and (d or w));
  y := w xor x xor t10 xor (c and z);
end;

procedure SBox3(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t02, t04, t05, t07, t08 : cardinal;
begin
  t02 := a or d;
  t04 := (a xor c) and t02;
  t05 := b or (a and d);
  t07 := d xor t04;
  t08 := c or (a and b);
  z := t08 xor b xor t07;
  y := t08 xor t02 xor (d and t05);
  w := (a or t07) xor (b and (d or z));
  x := t05 xor t04;
end;

procedure SBox3Inv(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t02, t03, t05 : cardinal;
begin
  t01 := c or d;
  t02 := a or d;
  t03 := c xor t02;
  t05 := a xor d;
  y := t05 xor ((b xor t02) and t03);
  w := (b and t01) xor t03;
  x := b xor ((a xor t03) and (w or t05));
  z := t01 xor t05 xor (b or (a and y));
end;

procedure SBox4(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t03, t04, t05, t06, t08, t11 : cardinal;
begin
  t03 := a xor (b or c);
  t04 := b xor d;
  t05 := d or t03;
  t06 := d and (a or b);
  z := t03 xor t06;
  t08 := z and t04;
  t11 := b and c;
  y := (t11 or t03) xor t08;
  x := (a and t05) xor (t11 or (t04 xor t08));
  w := not (c xor t06 xor (t04 and t05));
end;

procedure SBox4Inv(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t03, t04, t07, t09 : cardinal;
begin
  t01 := b or d;
  t03 := a and t01;
  t04 := b xor (c or d);
  t07 := a and t04;
  x := (c xor d) xor t07;
  t09 := x or (not t03);
  z := t03 xor d xor t04;
  y := t01 xor t09 xor (c or (a xor t07));
  w := a xor t04 xor t09;
end;

procedure SBox5(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t03, t05, t07, t08 : cardinal;
begin
  t01 := b xor d;
  t03 := a and t01;
  t05 := t03 xor c xor (b or d);
  w := not t05;
  t07 := a xor t01;
  t08 := d or w;
  y := (b or t05) xor (t07 or (d xor t08));
  x := t07 xor t08;
  z := (t03 or w) xor t01 xor (b or t07);
end;

procedure SBox5Inv(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t02 : cardinal;
begin
  t01 := a and d;
  t02 := c xor t01;
  w := a xor d xor (b and t02);
  x := t01 xor w xor (b or (a and c));
  z := t02 xor ((not b) or (a and w));
  y := b xor d xor t02 xor (w or x);
end;

procedure SBox6(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t03, t07 : cardinal;
begin
  t03 := a xor d;
  x := not ((a and d) xor b xor c);
  t07 := t03 and (b or c);
  y := not ((a or c) xor t07 xor (b and x));
  z := c xor (b or d) xor t07;
  w := a xor b xor y xor x and t03;
end;

procedure SBox6Inv(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t02, t05, t07 : cardinal;
begin
  t01 := a xor c;
  t02 := not c;
  t05 := d or (b and t01);
  t07 := a and (b or t02);
  x := b xor d xor (a or t02);
  w := not (t07 xor t05);
  z := a xor x xor t07 xor (t01 and t05);
  y := (d or t02) xor t01 xor (b and w);
end;

procedure SBox7(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t02, t04, t05 : cardinal;
begin
  t01 := a and c;
  t02 := not d;
  t04 := b or t01;
  t05 := a and b;
  z := (a and t02) xor c xor t04;
  x := (d or t05) xor a xor (c or z);
  w := c xor t05 xor (t02 or (t01 xor x));
  y := a xor ((t04 and z) or (b xor x));
end;

procedure SBox7Inv(a, b, c, d : cardinal;  var  w, x, y, z : cardinal);  register; 
var
  t01, t04, t06 : cardinal;
begin
  t01 := a and b;
  t04 := d and (a or b);
  z := (c or t01) xor t04;
  t06 := b xor t04;
  x := a xor (t06 or (not (d xor z)));
  w := c xor t06 xor (d or x);
  y := (c and (a or d)) xor (t01 or (b xor d));
end;


procedure ExpandKey(const Key : TSerpentKey; var {$ifndef B_X}ExpandedKey : TSerpentExpandedKey {$else}ExpandedKeyEx : TSerpentExpandedKeyEx {$endif});
var
  PreKey : array [0..139] of Cardinal;
  ExpKey : array [0..31] of byte;
  Index, Size : cardinal;
  {$ifdef B_X}
  ExpandedKey : PSerpentExpandedKey;
   {$endif}
begin
  {$ifdef B_X}
  ExpandedKey := PSerpentExpandedKey(@ExpandedKeyEx);
   {$endif}

  { expanding key to 256 bits }
  Size := Length(Key);
  if Size > 32 then Size := 32;
  if Size > 0 then
    SBMove(Key[0], ExpKey[0], Size);
  if Size < 32 then ExpKey[Size] := 1;
  if Size < 31 then
    FillChar(ExpKey[Size + 1], 32 - Size - 1, 0);
  { initializing pre-keys }
  PreKey[0] := ExpKey[ 0] or (ExpKey[ 1] shl 8)  or (ExpKey[02] shl 16) or (ExpKey[03] shl 24);
  PreKey[1] := ExpKey[ 4] or (ExpKey[ 5] shl 8)  or (ExpKey[06] shl 16) or (ExpKey[07] shl 24);
  PreKey[2] := ExpKey[ 8] or (ExpKey[ 9] shl 8)  or (ExpKey[10] shl 16) or (ExpKey[11] shl 24);
  PreKey[3] := ExpKey[12] or (ExpKey[13] shl 8)  or (ExpKey[14] shl 16) or (ExpKey[15] shl 24);
  PreKey[4] := ExpKey[16] or (ExpKey[17] shl 8)  or (ExpKey[18] shl 16) or (ExpKey[19] shl 24);
  PreKey[5] := ExpKey[20] or (ExpKey[21] shl 8)  or (ExpKey[22] shl 16) or (ExpKey[23] shl 24);
  PreKey[6] := ExpKey[24] or (ExpKey[25] shl 8)  or (ExpKey[26] shl 16) or (ExpKey[27] shl 24);
  PreKey[7] := ExpKey[28] or (ExpKey[29] shl 8)  or (ExpKey[30] shl 16) or (ExpKey[31] shl 24);
  { calculating pre-keys }
  for Index := 8 to 139 do
  begin
    PreKey[Index] := PreKey[Index - 8] xor PreKey[Index - 5] xor PreKey[Index - 3] xor
      PreKey[Index - 1] xor PHI xor Cardinal(Index - 8);
    PreKey[Index] := (PreKey[Index] shl 11) or (PreKey[Index] shr 21);
  end;

  { applying S-boxes }
  SBox3(PreKey[8], PreKey[9], PreKey[10], PreKey[11],
    ExpandedKey[0, 0], ExpandedKey[0, 1], ExpandedKey[0, 2], ExpandedKey[0, 3]);
  SBox2(PreKey[12], PreKey[13], PreKey[14], PreKey[15],
    ExpandedKey[1, 0], ExpandedKey[1, 1], ExpandedKey[1, 2], ExpandedKey[1, 3]);
  SBox1(PreKey[16], PreKey[17], PreKey[18], PreKey[19],
    ExpandedKey[2, 0], ExpandedKey[2, 1], ExpandedKey[2, 2], ExpandedKey[2, 3]);
  SBox0(PreKey[20], PreKey[21], PreKey[22], PreKey[23],
    ExpandedKey[3, 0], ExpandedKey[3, 1], ExpandedKey[3, 2], ExpandedKey[3, 3]);
  SBox7(PreKey[24], PreKey[25], PreKey[26], PreKey[27],
    ExpandedKey[4, 0], ExpandedKey[4, 1], ExpandedKey[4, 2], ExpandedKey[4, 3]);
  SBox6(PreKey[28], PreKey[29], PreKey[30], PreKey[31],
    ExpandedKey[5, 0], ExpandedKey[5, 1], ExpandedKey[5, 2], ExpandedKey[5, 3]);
  SBox5(PreKey[32], PreKey[33], PreKey[34], PreKey[35],
    ExpandedKey[6, 0], ExpandedKey[6, 1], ExpandedKey[6, 2], ExpandedKey[6, 3]);
  SBox4(PreKey[36], PreKey[37], PreKey[38], PreKey[39],
    ExpandedKey[7, 0], ExpandedKey[7, 1], ExpandedKey[7, 2], ExpandedKey[7, 3]);
  SBox3(PreKey[40], PreKey[41], PreKey[42], PreKey[43],
    ExpandedKey[8, 0], ExpandedKey[8, 1], ExpandedKey[8, 2], ExpandedKey[8, 3]);
  SBox2(PreKey[44], PreKey[45], PreKey[46], PreKey[47],
    ExpandedKey[9, 0], ExpandedKey[9, 1], ExpandedKey[9, 2], ExpandedKey[9, 3]);
  SBox1(PreKey[48], PreKey[49], PreKey[50], PreKey[51],
    ExpandedKey[10, 0], ExpandedKey[10, 1], ExpandedKey[10, 2], ExpandedKey[10, 3]);
  SBox0(PreKey[52], PreKey[53], PreKey[54], PreKey[55],
    ExpandedKey[11, 0], ExpandedKey[11, 1], ExpandedKey[11, 2], ExpandedKey[11, 3]);
  SBox7(PreKey[56], PreKey[57], PreKey[58], PreKey[59],
    ExpandedKey[12, 0], ExpandedKey[12, 1], ExpandedKey[12, 2], ExpandedKey[12, 3]);
  SBox6(PreKey[60], PreKey[61], PreKey[62], PreKey[63],
    ExpandedKey[13, 0], ExpandedKey[13, 1], ExpandedKey[13, 2], ExpandedKey[13, 3]);
  SBox5(PreKey[64], PreKey[65], PreKey[66], PreKey[67],
    ExpandedKey[14, 0], ExpandedKey[14, 1], ExpandedKey[14, 2], ExpandedKey[14, 3]);
  SBox4(PreKey[68], PreKey[69], PreKey[70], PreKey[71],
    ExpandedKey[15, 0], ExpandedKey[15, 1], ExpandedKey[15, 2], ExpandedKey[15, 3]);
  SBox3(PreKey[72], PreKey[73], PreKey[74], PreKey[75],
    ExpandedKey[16, 0], ExpandedKey[16, 1], ExpandedKey[16, 2], ExpandedKey[16, 3]);
  SBox2(PreKey[76], PreKey[77], PreKey[78], PreKey[79],
    ExpandedKey[17, 0], ExpandedKey[17, 1], ExpandedKey[17, 2], ExpandedKey[17, 3]);
  SBox1(PreKey[80], PreKey[81], PreKey[82], PreKey[83],
    ExpandedKey[18, 0], ExpandedKey[18, 1], ExpandedKey[18, 2], ExpandedKey[18, 3]);
  SBox0(PreKey[84], PreKey[85], PreKey[86], PreKey[87],
    ExpandedKey[19, 0], ExpandedKey[19, 1], ExpandedKey[19, 2], ExpandedKey[19, 3]);
  SBox7(PreKey[88], PreKey[89], PreKey[90], PreKey[91],
    ExpandedKey[20, 0], ExpandedKey[20, 1], ExpandedKey[20, 2], ExpandedKey[20, 3]);
  SBox6(PreKey[92], PreKey[93], PreKey[94], PreKey[95],
    ExpandedKey[21, 0], ExpandedKey[21, 1], ExpandedKey[21, 2], ExpandedKey[21, 3]);
  SBox5(PreKey[96], PreKey[97], PreKey[98], PreKey[99],
    ExpandedKey[22, 0], ExpandedKey[22, 1], ExpandedKey[22, 2], ExpandedKey[22, 3]);
  SBox4(PreKey[100], PreKey[101], PreKey[102], PreKey[103],
    ExpandedKey[23, 0], ExpandedKey[23, 1], ExpandedKey[23, 2], ExpandedKey[23, 3]);
  SBox3(PreKey[104], PreKey[105], PreKey[106], PreKey[107],
    ExpandedKey[24, 0], ExpandedKey[24, 1], ExpandedKey[24, 2], ExpandedKey[24, 3]);
  SBox2(PreKey[108], PreKey[109], PreKey[110], PreKey[111],
    ExpandedKey[25, 0], ExpandedKey[25, 1], ExpandedKey[25, 2], ExpandedKey[25, 3]);
  SBox1(PreKey[112], PreKey[113], PreKey[114], PreKey[115],
    ExpandedKey[26, 0], ExpandedKey[26, 1], ExpandedKey[26, 2], ExpandedKey[26, 3]);
  SBox0(PreKey[116], PreKey[117], PreKey[118], PreKey[119],
    ExpandedKey[27, 0], ExpandedKey[27, 1], ExpandedKey[27, 2], ExpandedKey[27, 3]);
  SBox7(PreKey[120], PreKey[121], PreKey[122], PreKey[123],
    ExpandedKey[28, 0], ExpandedKey[28, 1], ExpandedKey[28, 2], ExpandedKey[28, 3]);
  SBox6(PreKey[124], PreKey[125], PreKey[126], PreKey[127],
    ExpandedKey[29, 0], ExpandedKey[29, 1], ExpandedKey[29, 2], ExpandedKey[29, 3]);
  SBox5(PreKey[128], PreKey[129], PreKey[130], PreKey[131],
    ExpandedKey[30, 0], ExpandedKey[30, 1], ExpandedKey[30, 2], ExpandedKey[30, 3]);
  SBox4(PreKey[132], PreKey[133], PreKey[134], PreKey[135],
    ExpandedKey[31, 0], ExpandedKey[31, 1], ExpandedKey[31, 2], ExpandedKey[31, 3]);
  SBox3(PreKey[136], PreKey[137], PreKey[138], PreKey[139],
    ExpandedKey[32, 0], ExpandedKey[32, 1], ExpandedKey[32, 2], ExpandedKey[32, 3]);
end;

procedure EncryptBlock(var B0, B1, B2, B3 : cardinal; const {$ifndef B_X}ExpandedKey : TSerpentExpandedKey {$else}ExpandedKeyEx : TSerpentExpandedKeyEx {$endif});
var
  X0, X1, X2, X3, Y0, Y1, Y2, Y3 : cardinal;
  {$ifdef B_X}
  ExpandedKey : PSerpentExpandedKey;
   {$endif}
begin
  {$ifdef B_X}
  ExpandedKey := PSerpentExpandedKey(@ExpandedKeyEx);
   {$endif}

  { round 0 }

  X0 := B0 xor ExpandedKey[0, 0]; X1 := B1 xor ExpandedKey[0, 1];
  X2 := B2 xor ExpandedKey[0, 2]; X3 := B3 xor ExpandedKey[0, 3];

  SBox0(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 1 }

  X0 := X0 xor ExpandedKey[1, 0]; X1 := X1 xor ExpandedKey[1, 1];
  X2 := X2 xor ExpandedKey[1, 2]; X3 := X3 xor ExpandedKey[1, 3];

  SBox1(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 2 }

  X0 := X0 xor ExpandedKey[2, 0]; X1 := X1 xor ExpandedKey[2, 1];
  X2 := X2 xor ExpandedKey[2, 2]; X3 := X3 xor ExpandedKey[2, 3];

  SBox2(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 3 }

  X0 := X0 xor ExpandedKey[3, 0]; X1 := X1 xor ExpandedKey[3, 1];
  X2 := X2 xor ExpandedKey[3, 2]; X3 := X3 xor ExpandedKey[3, 3];

  SBox3(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 4 }

  X0 := X0 xor ExpandedKey[4, 0]; X1 := X1 xor ExpandedKey[4, 1];
  X2 := X2 xor ExpandedKey[4, 2]; X3 := X3 xor ExpandedKey[4, 3];

  SBox4(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 5 }

  X0 := X0 xor ExpandedKey[5, 0]; X1 := X1 xor ExpandedKey[5, 1];
  X2 := X2 xor ExpandedKey[5, 2]; X3 := X3 xor ExpandedKey[5, 3];

  SBox5(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 6 }

  X0 := X0 xor ExpandedKey[6, 0]; X1 := X1 xor ExpandedKey[6, 1];
  X2 := X2 xor ExpandedKey[6, 2]; X3 := X3 xor ExpandedKey[6, 3];

  SBox6(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 7 }

  X0 := X0 xor ExpandedKey[7, 0]; X1 := X1 xor ExpandedKey[7, 1];
  X2 := X2 xor ExpandedKey[7, 2]; X3 := X3 xor ExpandedKey[7, 3];

  SBox7(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 8 }

  X0 := X0 xor ExpandedKey[8, 0]; X1 := X1 xor ExpandedKey[8, 1];
  X2 := X2 xor ExpandedKey[8, 2]; X3 := X3 xor ExpandedKey[8, 3];

  SBox0(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 9 }

  X0 := X0 xor ExpandedKey[9, 0]; X1 := X1 xor ExpandedKey[9, 1];
  X2 := X2 xor ExpandedKey[9, 2]; X3 := X3 xor ExpandedKey[9, 3];

  SBox1(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 10 }

  X0 := X0 xor ExpandedKey[10, 0]; X1 := X1 xor ExpandedKey[10, 1];
  X2 := X2 xor ExpandedKey[10, 2]; X3 := X3 xor ExpandedKey[10, 3];

  SBox2(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 11 }

  X0 := X0 xor ExpandedKey[11, 0]; X1 := X1 xor ExpandedKey[11, 1];
  X2 := X2 xor ExpandedKey[11, 2]; X3 := X3 xor ExpandedKey[11, 3];

  SBox3(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 12 }

  X0 := X0 xor ExpandedKey[12, 0]; X1 := X1 xor ExpandedKey[12, 1];
  X2 := X2 xor ExpandedKey[12, 2]; X3 := X3 xor ExpandedKey[12, 3];

  SBox4(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 13 }

  X0 := X0 xor ExpandedKey[13, 0]; X1 := X1 xor ExpandedKey[13, 1];
  X2 := X2 xor ExpandedKey[13, 2]; X3 := X3 xor ExpandedKey[13, 3];

  SBox5(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 14 }

  X0 := X0 xor ExpandedKey[14, 0]; X1 := X1 xor ExpandedKey[14, 1];
  X2 := X2 xor ExpandedKey[14, 2]; X3 := X3 xor ExpandedKey[14, 3];

  SBox6(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 15 }

  X0 := X0 xor ExpandedKey[15, 0]; X1 := X1 xor ExpandedKey[15, 1];
  X2 := X2 xor ExpandedKey[15, 2]; X3 := X3 xor ExpandedKey[15, 3];

  SBox7(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 16 }

  X0 := X0 xor ExpandedKey[16, 0]; X1 := X1 xor ExpandedKey[16, 1];
  X2 := X2 xor ExpandedKey[16, 2]; X3 := X3 xor ExpandedKey[16, 3];

  SBox0(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 17 }

  X0 := X0 xor ExpandedKey[17, 0]; X1 := X1 xor ExpandedKey[17, 1];
  X2 := X2 xor ExpandedKey[17, 2]; X3 := X3 xor ExpandedKey[17, 3];

  SBox1(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 18 }

  X0 := X0 xor ExpandedKey[18, 0]; X1 := X1 xor ExpandedKey[18, 1];
  X2 := X2 xor ExpandedKey[18, 2]; X3 := X3 xor ExpandedKey[18, 3];

  SBox2(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 19 }

  X0 := X0 xor ExpandedKey[19, 0]; X1 := X1 xor ExpandedKey[19, 1];
  X2 := X2 xor ExpandedKey[19, 2]; X3 := X3 xor ExpandedKey[19, 3];

  SBox3(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 20 }

  X0 := X0 xor ExpandedKey[20, 0]; X1 := X1 xor ExpandedKey[20, 1];
  X2 := X2 xor ExpandedKey[20, 2]; X3 := X3 xor ExpandedKey[20, 3];

  SBox4(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 21 }

  X0 := X0 xor ExpandedKey[21, 0]; X1 := X1 xor ExpandedKey[21, 1];
  X2 := X2 xor ExpandedKey[21, 2]; X3 := X3 xor ExpandedKey[21, 3];

  SBox5(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 22 }

  X0 := X0 xor ExpandedKey[22, 0]; X1 := X1 xor ExpandedKey[22, 1];
  X2 := X2 xor ExpandedKey[22, 2]; X3 := X3 xor ExpandedKey[22, 3];

  SBox6(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 23 }

  X0 := X0 xor ExpandedKey[23, 0]; X1 := X1 xor ExpandedKey[23, 1];
  X2 := X2 xor ExpandedKey[23, 2]; X3 := X3 xor ExpandedKey[23, 3];

  SBox7(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 24 }

  X0 := X0 xor ExpandedKey[24, 0]; X1 := X1 xor ExpandedKey[24, 1];
  X2 := X2 xor ExpandedKey[24, 2]; X3 := X3 xor ExpandedKey[24, 3];

  SBox0(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 25 }

  X0 := X0 xor ExpandedKey[25, 0]; X1 := X1 xor ExpandedKey[25, 1];
  X2 := X2 xor ExpandedKey[25, 2]; X3 := X3 xor ExpandedKey[25, 3];

  SBox1(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 26 }

  X0 := X0 xor ExpandedKey[26, 0]; X1 := X1 xor ExpandedKey[26, 1];
  X2 := X2 xor ExpandedKey[26, 2]; X3 := X3 xor ExpandedKey[26, 3];

  SBox2(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 27 }

  X0 := X0 xor ExpandedKey[27, 0]; X1 := X1 xor ExpandedKey[27, 1];
  X2 := X2 xor ExpandedKey[27, 2]; X3 := X3 xor ExpandedKey[27, 3];

  SBox3(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 28 }

  X0 := X0 xor ExpandedKey[28, 0]; X1 := X1 xor ExpandedKey[28, 1];
  X2 := X2 xor ExpandedKey[28, 2]; X3 := X3 xor ExpandedKey[28, 3];

  SBox4(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 29 }

  X0 := X0 xor ExpandedKey[29, 0]; X1 := X1 xor ExpandedKey[29, 1];
  X2 := X2 xor ExpandedKey[29, 2]; X3 := X3 xor ExpandedKey[29, 3];

  SBox5(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 30 }

  X0 := X0 xor ExpandedKey[30, 0]; X1 := X1 xor ExpandedKey[30, 1];
  X2 := X2 xor ExpandedKey[30, 2]; X3 := X3 xor ExpandedKey[30, 3];

  SBox6(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := (Y0 shl 13) or (Y0 shr 19);
  X2 := (Y2 shl 3) or (Y2 shr 29);
  X1 := Y1 xor X0 xor X2;
  X3 := Y3 xor X2 xor (X0 shl 3);
  X1 := (X1 shl 1) or (X1 shr 31);
  X3 := (X3 shl 7) or (X3 shr 25);
  X0 := X0 xor X1 xor X3;
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := (X0 shl 5) or (X0 shr 27);
  X2 := (X2 shl 22) or (X2 shr 10);

  { round 31 }

  X0 := X0 xor ExpandedKey[31, 0]; X1 := X1 xor ExpandedKey[31, 1];
  X2 := X2 xor ExpandedKey[31, 2]; X3 := X3 xor ExpandedKey[31, 3];

  SBox7(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  B0 := Y0 xor ExpandedKey[32, 0];
  B1 := Y1 xor ExpandedKey[32, 1];
  B2 := Y2 xor ExpandedKey[32, 2];
  B3 := Y3 xor ExpandedKey[32, 3];
end;


procedure DecryptBlock(var B0, B1, B2, B3 : cardinal; const {$ifndef B_X}ExpandedKey : TSerpentExpandedKey {$else}ExpandedKeyEx : TSerpentExpandedKeyEx {$endif});
var
  X0, X1, X2, X3, Y0, Y1, Y2, Y3 : cardinal;
  {$ifdef B_X}
  ExpandedKey : PSerpentExpandedKey;
   {$endif}
begin
  {$ifdef B_X}
  ExpandedKey := PSerpentExpandedKey(@ExpandedKeyEx);
   {$endif}

  { round 31 }
  X0 := B0 xor ExpandedKey[32, 0]; X1 := B1 xor ExpandedKey[32, 1];
  X2 := B2 xor ExpandedKey[32, 2]; X3 := B3 xor ExpandedKey[32, 3];

  SBox7Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[31, 0]; X1 := Y1 xor ExpandedKey[31, 1];
  X2 := Y2 xor ExpandedKey[31, 2]; X3 := Y3 xor ExpandedKey[31, 3];

  { round 30 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox6Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[30, 0]; X1 := Y1 xor ExpandedKey[30, 1];
  X2 := Y2 xor ExpandedKey[30, 2]; X3 := Y3 xor ExpandedKey[30, 3];

  { round 29 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox5Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[29, 0]; X1 := Y1 xor ExpandedKey[29, 1];
  X2 := Y2 xor ExpandedKey[29, 2]; X3 := Y3 xor ExpandedKey[29, 3];

  { round 28 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox4Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[28, 0]; X1 := Y1 xor ExpandedKey[28, 1];
  X2 := Y2 xor ExpandedKey[28, 2]; X3 := Y3 xor ExpandedKey[28, 3];

  { round 27 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox3Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[27, 0]; X1 := Y1 xor ExpandedKey[27, 1];
  X2 := Y2 xor ExpandedKey[27, 2]; X3 := Y3 xor ExpandedKey[27, 3];

  { round 26 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox2Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[26, 0]; X1 := Y1 xor ExpandedKey[26, 1];
  X2 := Y2 xor ExpandedKey[26, 2]; X3 := Y3 xor ExpandedKey[26, 3];

  { round 25 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox1Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[25, 0]; X1 := Y1 xor ExpandedKey[25, 1];
  X2 := Y2 xor ExpandedKey[25, 2]; X3 := Y3 xor ExpandedKey[25, 3];

  { round 24 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox0Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[24, 0]; X1 := Y1 xor ExpandedKey[24, 1];
  X2 := Y2 xor ExpandedKey[24, 2]; X3 := Y3 xor ExpandedKey[24, 3];

  { round 23 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox7Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[23, 0]; X1 := Y1 xor ExpandedKey[23, 1];
  X2 := Y2 xor ExpandedKey[23, 2]; X3 := Y3 xor ExpandedKey[23, 3];

  { round 22 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox6Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[22, 0]; X1 := Y1 xor ExpandedKey[22, 1];
  X2 := Y2 xor ExpandedKey[22, 2]; X3 := Y3 xor ExpandedKey[22, 3];

  { round 21 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox5Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[21, 0]; X1 := Y1 xor ExpandedKey[21, 1];
  X2 := Y2 xor ExpandedKey[21, 2]; X3 := Y3 xor ExpandedKey[21, 3];

  { round 20 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox4Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[20, 0]; X1 := Y1 xor ExpandedKey[20, 1];
  X2 := Y2 xor ExpandedKey[20, 2]; X3 := Y3 xor ExpandedKey[20, 3];

  { round 19 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox3Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[19, 0]; X1 := Y1 xor ExpandedKey[19, 1];
  X2 := Y2 xor ExpandedKey[19, 2]; X3 := Y3 xor ExpandedKey[19, 3];

  { round 18 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox2Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[18, 0]; X1 := Y1 xor ExpandedKey[18, 1];
  X2 := Y2 xor ExpandedKey[18, 2]; X3 := Y3 xor ExpandedKey[18, 3];

  { round 17 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox1Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[17, 0]; X1 := Y1 xor ExpandedKey[17, 1];
  X2 := Y2 xor ExpandedKey[17, 2]; X3 := Y3 xor ExpandedKey[17, 3];

  { round 16 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox0Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[16, 0]; X1 := Y1 xor ExpandedKey[16, 1];
  X2 := Y2 xor ExpandedKey[16, 2]; X3 := Y3 xor ExpandedKey[16, 3];

  { round 15 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox7Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[15, 0]; X1 := Y1 xor ExpandedKey[15, 1];
  X2 := Y2 xor ExpandedKey[15, 2]; X3 := Y3 xor ExpandedKey[15, 3];

  { round 14 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox6Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[14, 0]; X1 := Y1 xor ExpandedKey[14, 1];
  X2 := Y2 xor ExpandedKey[14, 2]; X3 := Y3 xor ExpandedKey[14, 3];

  { round 13 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox5Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[13, 0]; X1 := Y1 xor ExpandedKey[13, 1];
  X2 := Y2 xor ExpandedKey[13, 2]; X3 := Y3 xor ExpandedKey[13, 3];

  { round 12 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox4Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[12, 0]; X1 := Y1 xor ExpandedKey[12, 1];
  X2 := Y2 xor ExpandedKey[12, 2]; X3 := Y3 xor ExpandedKey[12, 3];

  { round 11 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox3Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[11, 0]; X1 := Y1 xor ExpandedKey[11, 1];
  X2 := Y2 xor ExpandedKey[11, 2]; X3 := Y3 xor ExpandedKey[11, 3];

  { round 10 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox2Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[10, 0]; X1 := Y1 xor ExpandedKey[10, 1];
  X2 := Y2 xor ExpandedKey[10, 2]; X3 := Y3 xor ExpandedKey[10, 3];

  { round 9 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox1Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[9, 0]; X1 := Y1 xor ExpandedKey[9, 1];
  X2 := Y2 xor ExpandedKey[9, 2]; X3 := Y3 xor ExpandedKey[9, 3];

  { round 8 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox0Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[8, 0]; X1 := Y1 xor ExpandedKey[8, 1];
  X2 := Y2 xor ExpandedKey[8, 2]; X3 := Y3 xor ExpandedKey[8, 3];

  { round 7 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox7Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[7, 0]; X1 := Y1 xor ExpandedKey[7, 1];
  X2 := Y2 xor ExpandedKey[7, 2]; X3 := Y3 xor ExpandedKey[7, 3];

  { round 6 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox6Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[6, 0]; X1 := Y1 xor ExpandedKey[6, 1];
  X2 := Y2 xor ExpandedKey[6, 2]; X3 := Y3 xor ExpandedKey[6, 3];

  { round 5 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox5Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[5, 0]; X1 := Y1 xor ExpandedKey[5, 1];
  X2 := Y2 xor ExpandedKey[5, 2]; X3 := Y3 xor ExpandedKey[5, 3];

  { round 4 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox4Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[4, 0]; X1 := Y1 xor ExpandedKey[4, 1];
  X2 := Y2 xor ExpandedKey[4, 2]; X3 := Y3 xor ExpandedKey[4, 3];

  { round 3 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox3Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[3, 0]; X1 := Y1 xor ExpandedKey[3, 1];
  X2 := Y2 xor ExpandedKey[3, 2]; X3 := Y3 xor ExpandedKey[3, 3];

  { round 2 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox2Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[2, 0]; X1 := Y1 xor ExpandedKey[2, 1];
  X2 := Y2 xor ExpandedKey[2, 2]; X3 := Y3 xor ExpandedKey[2, 3];

  { round 1 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox1Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  X0 := Y0 xor ExpandedKey[1, 0]; X1 := Y1 xor ExpandedKey[1, 1];
  X2 := Y2 xor ExpandedKey[1, 2]; X3 := Y3 xor ExpandedKey[1, 3];

  { round 0 }

  X2 := (X2 shr 22) or (X2 shl 10);
  X0 := (X0 shr 5) or (X0 shl 27);
  X2 := X2 xor X3 xor (X1 shl 7);
  X0 := X0 xor X1 xor X3;
  X3 := (X3 shr 7) or (X3 shl 25);
  X1 := (X1 shr 1) or (X1 shl 31);
  X3 := X3 xor X2 xor (X0 shl 3);
  X1 := X1 xor X0 xor X2;
  X2 := (X2 shr 3) or (X2 shl 29);
  X0 := (X0 shr 13) or (X0 shl 19);

  SBox0Inv(X0, X1, X2, X3, Y0, Y1, Y2, Y3);

  B0 := Y0 xor ExpandedKey[0, 0]; B1 := Y1 xor ExpandedKey[0, 1];
  B2 := Y2 xor ExpandedKey[0, 2]; B3 := Y3 xor ExpandedKey[0, 3];
end;

end.
