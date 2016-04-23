(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBMath;

interface

uses
  SBTypes,
  SysUtils;


const
  MAXDIGIT = 768;
  RandKeyLength = 2; { ...Bases }

type
  TRC4Random =  record
    S: array  [0..255]  of Byte;
    I, J: Integer;
  end;

  TRC4RandomContext =  record
    S: array  [0..255]  of Byte;
    I, J: Integer;
    RandomInit: Boolean;
  end;

  TSBInt64 = Int64;

  TSBMathProgressFunc =  function(Data :  pointer ): boolean of object;
  EElMathException =  class( Exception );

type

  PLInt = ^TLInt;
  TLInt = record
    Length: Integer;
    Digits: array[1..MAXDIGIT] of LongWord;
    Sign: Boolean;
  end;


procedure LShl(var Num: PLInt); 
procedure LShlEx(var Num: PLInt; Bits : integer); 
procedure LShlNum(Src, Dest: PLInt; Bits: Integer); 
procedure LShr(var Num: PLInt); 
procedure LShrEx(var Num: PLInt; Bits : integer); 
procedure LShrNum(X: PLInt; var Res: PLInt; Bits: Cardinal); 
procedure LShiftLeft(var A: PLInt; N: LongWord); 

procedure LAdd(A, B: PLInt;  C: PLInt);  overload; 
procedure LAdd(A: PLInt; B : LongWord;  C: PLInt);  overload; 
procedure LSub(A, B: PLInt; var PTm: PLInt);  overload; 
procedure LSub(A: PLInt; B : LongWord; var PTm: PLInt);  overload; 
procedure LDec(var A: PLInt); 
procedure LInc(var A: PLInt); 
procedure LMultSh(A: PLInt; B: LongWord;  Res: PLInt); 
procedure LMult(A, B: PLInt; var Res: PLInt); 
procedure LModSh(A: PLInt; B: LongWord; var Res: LongWord); 
procedure LMod(X, N: PLInt; var Res: PLInt); 
procedure LModEx(X, N : PLInt; var Res : PLInt); 
procedure LDivSh(A: PLInt; B: LongWord; Q, R: PLInt); 
procedure LDiv(A, B: PLInt; var C, D: PLInt); 
procedure LModPower(A, E, N: PLInt; var Res: PLInt); 
procedure LMontgomery(A, B, N: PLInt; var Res: PLInt); 
procedure LGCD(B, A: PLInt; var C, D: PLInt); 
procedure LSwap(var A, B: PLInt); 
function LBitCount(A: PLInt): LongWord; 
function LBitSet(A : PLInt; n : integer) : boolean; 
procedure LSetBit(var A : PLInt; n : integer; Value : boolean);
procedure LBitTruncate(var A : PLInt; Bits : integer);

function LGreater(A, B: PLInt): Boolean; 
function LEqual(A, B: PLInt): Boolean; 
function LEven(A: PLInt): Boolean; 
function LNull(A: PLInt): Boolean; 
procedure LCopy(var P: PLInt; A: PLInt); 

procedure LZero(var A: PLInt); 
function LToStr(A: PLInt): string; 
function LToBase64(A: PLInt): string; 
procedure LInit(var P: PLInt; Num: string);  overload ;
procedure LInit(var P: PLInt; Num: LongWord);  overload ;
procedure LInit(var P: PLInt; Num: Int64);  overload ;
procedure LGenerate(var R: PLInt; Len: Integer); 
procedure LCreate({$ifndef BUILDER_USED}out {$else}var {$endif} A: PLInt); 
procedure LDestroy(var P: PLInt); 
procedure LTrim(var A: PLInt); 

function HexToDecDigit(A: Char): Integer; 
function DecToHexDigit(A: Integer): Char; 
function DecToHex(A: LongWord): string; 

{$ifndef SB_MSSQL}
procedure LBAddPowB(Src, Dest: PLInt; Bases: Cardinal); 
procedure LBM(SrcMod, Dest: PLInt; Bits: Cardinal); 
procedure LBDivPowB(Src, Dest: PLInt; Bases: Cardinal); 
procedure LBModPowB(Src, Dest: PLInt; Bases: Cardinal); 
procedure LBMul(SrcA, SrcB, Dest: PLInt; FromBases, ToBases: Cardinal); 
procedure LBMod(Src, SrcMod, SrcM: PLInt; var Dest: PLInt; Bits: Cardinal); 
procedure LBPowMod(SrcA, SrcB, SrcMod: PLInt; var Dest: PLInt; ModInv: PLInt); 
 {$endif}

procedure LMMul(A, B, N: PLInt; var Res: PLInt); 
procedure LMModPower(X, E, N: PLInt; var Res: PLInt; ProgressFunc : TSBMathProgressFunc  =  nil;
  Data :  pointer   =  nil; RaiseExceptionOnCancel : boolean  =  false); 
function LRabinMillerPrimeTest(P: PLInt;
  ProgressFunc : TSBMathProgressFunc  =  nil; Data :  pointer   =  nil;
  RaiseExceptionOnCancel: boolean  =  false): Boolean; 
function LIsPrime(P: PLInt;
  ProgressFunc : TSBMathProgressFunc  =  nil; Data :  pointer   =  nil;
  RaiseExceptionOnCancel: boolean  =  false): Boolean; 
{$ifndef SB_PGPSFX_STUB}
procedure LGenPrime(P: PLInt; Len: Integer; RSAPrime: boolean {$ifdef HAS_DEF_PARAMS} = false {$endif};
  ProgressFunc : TSBMathProgressFunc  =  nil; Data :  pointer   =  nil;
  RaiseExceptionOnCancel : boolean  =  false); 
procedure LGenPrimeEx(P: PLInt; Bits: Integer; RSAPrime: boolean{$ifdef HAS_DEF_PARAMS} =  false {$endif};
  ProgressFunc : TSBMathProgressFunc  =  nil; Data :  pointer   =  nil;
  RaiseExceptionOnCancel: boolean  =  false);
 {$endif SB_PGPSFX_STUB}

procedure LRC4Randomize(var Ctx: TRC4RandomContext; Key: PLInt); 
procedure LRC4Init(var Ctx: TRC4RandomContext); 
function LRC4RandomByte(var Ctx: TRC4RandomContext): Byte; 
procedure LRandom(var Ctx: TRC4RandomContext; A: PLInt; Bytes: Integer); 


function MathOperationCanceled(ProgressFunc : TSBMathProgressFunc; Data :  pointer ): boolean; 


resourcestring
  sNumberTooLarge = 'Number too large';
  sDivisionByZero = 'Division by zero';

implementation

uses
  SBEncoding,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBRandom;

type
  TSuperBaseRec =  packed  record
    Lo, Hi: LongWord;
  end;

{$ifndef SB_PGPSFX_STUB}
const
  SmallPrimesCount = 2048;
  SmallPrimes: array[0..SmallPrimesCount - 1] of Cardinal =
     ( 
    2, 3, 5, 7, 11, 13, 17, 19,
    23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89,
    97, 101, 103, 107, 109, 113, 127, 131,
    137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223,
    227, 229, 233, 239, 241, 251, 257, 263,
    269, 271, 277, 281, 283, 293, 307, 311,
    313, 317, 331, 337, 347, 349, 353, 359,
    367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457,
    461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569,
    571, 577, 587, 593, 599, 601, 607, 613,
    617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719,
    727, 733, 739, 743, 751, 757, 761, 769,
    773, 787, 797, 809, 811, 821, 823, 827,
    829, 839, 853, 857, 859, 863, 877, 881,
    883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997,
    1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
    1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
    1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
    1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
    1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
    1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321,
    1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423,
    1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459,
    1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
    1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571,
    1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619,
    1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693,
    1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747,
    1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811,
    1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
    1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949,
    1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003,
    2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069,
    2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,
    2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203,
    2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267,
    2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311,
    2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377,
    2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
    2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503,
    2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579,
    2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657,
    2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693,
    2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741,
    2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801,
    2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861,
    2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939,
    2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011,
    3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079,
    3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167,
    3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221,
    3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301,
    3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347,
    3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
    3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491,
    3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541,
    3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607,
    3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671,
    3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727,
    3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797,
    3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863,
    3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923,
    3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003,
    4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057,
    4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129,
    4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211,
    4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259,
    4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337,
    4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409,
    4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481,
    4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547,
    4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621,
    4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673,
    4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
    4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813,
    4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909,
    4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967,
    4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011,
    5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
    5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167,
    5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233,
    5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309,
    5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399,
    5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
    5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507,
    5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573,
    5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653,
    5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711,
    5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
    5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849,
    5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897,
    5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007,
    6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073,
    6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
    6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211,
    6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271,
    6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329,
    6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379,
    6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,
    6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563,
    6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637,
    6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701,
    6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779,
    6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
    6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907,
    6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971,
    6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027,
    7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121,
    7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
    7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253,
    7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349,
    7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457,
    7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517,
    7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
    7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621,
    7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691,
    7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757,
    7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853,
    7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
    7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009,
    8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087,
    8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161,
    8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231,
    8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291,
    8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369,
    8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443,
    8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537,
    8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609,
    8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677,
    8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731,
    8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803,
    8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861,
    8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941,
    8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011,
    9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091,
    9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161,
    9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227,
    9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311,
    9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377,
    9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433,
    9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491,
    9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587,
    9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649,
    9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733,
    9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791,
    9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857,
    9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929,
    9931, 9941, 9949, 9967, 9973, 10007, 10009, 10037,
    10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099,
    10103, 10111, 10133, 10139, 10141, 10151, 10159, 10163,
    10169, 10177, 10181, 10193, 10211, 10223, 10243, 10247,
    10253, 10259, 10267, 10271, 10273, 10289, 10301, 10303,
    10313, 10321, 10331, 10333, 10337, 10343, 10357, 10369,
    10391, 10399, 10427, 10429, 10433, 10453, 10457, 10459,
    10463, 10477, 10487, 10499, 10501, 10513, 10529, 10531,
    10559, 10567, 10589, 10597, 10601, 10607, 10613, 10627,
    10631, 10639, 10651, 10657, 10663, 10667, 10687, 10691,
    10709, 10711, 10723, 10729, 10733, 10739, 10753, 10771,
    10781, 10789, 10799, 10831, 10837, 10847, 10853, 10859,
    10861, 10867, 10883, 10889, 10891, 10903, 10909, 10937,
    10939, 10949, 10957, 10973, 10979, 10987, 10993, 11003,
    11027, 11047, 11057, 11059, 11069, 11071, 11083, 11087,
    11093, 11113, 11117, 11119, 11131, 11149, 11159, 11161,
    11171, 11173, 11177, 11197, 11213, 11239, 11243, 11251,
    11257, 11261, 11273, 11279, 11287, 11299, 11311, 11317,
    11321, 11329, 11351, 11353, 11369, 11383, 11393, 11399,
    11411, 11423, 11437, 11443, 11447, 11467, 11471, 11483,
    11489, 11491, 11497, 11503, 11519, 11527, 11549, 11551,
    11579, 11587, 11593, 11597, 11617, 11621, 11633, 11657,
    11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731,
    11743, 11777, 11779, 11783, 11789, 11801, 11807, 11813,
    11821, 11827, 11831, 11833, 11839, 11863, 11867, 11887,
    11897, 11903, 11909, 11923, 11927, 11933, 11939, 11941,
    11953, 11959, 11969, 11971, 11981, 11987, 12007, 12011,
    12037, 12041, 12043, 12049, 12071, 12073, 12097, 12101,
    12107, 12109, 12113, 12119, 12143, 12149, 12157, 12161,
    12163, 12197, 12203, 12211, 12227, 12239, 12241, 12251,
    12253, 12263, 12269, 12277, 12281, 12289, 12301, 12323,
    12329, 12343, 12347, 12373, 12377, 12379, 12391, 12401,
    12409, 12413, 12421, 12433, 12437, 12451, 12457, 12473,
    12479, 12487, 12491, 12497, 12503, 12511, 12517, 12527,
    12539, 12541, 12547, 12553, 12569, 12577, 12583, 12589,
    12601, 12611, 12613, 12619, 12637, 12641, 12647, 12653,
    12659, 12671, 12689, 12697, 12703, 12713, 12721, 12739,
    12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821,
    12823, 12829, 12841, 12853, 12889, 12893, 12899, 12907,
    12911, 12917, 12919, 12923, 12941, 12953, 12959, 12967,
    12973, 12979, 12983, 13001, 13003, 13007, 13009, 13033,
    13037, 13043, 13049, 13063, 13093, 13099, 13103, 13109,
    13121, 13127, 13147, 13151, 13159, 13163, 13171, 13177,
    13183, 13187, 13217, 13219, 13229, 13241, 13249, 13259,
    13267, 13291, 13297, 13309, 13313, 13327, 13331, 13337,
    13339, 13367, 13381, 13397, 13399, 13411, 13417, 13421,
    13441, 13451, 13457, 13463, 13469, 13477, 13487, 13499,
    13513, 13523, 13537, 13553, 13567, 13577, 13591, 13597,
    13613, 13619, 13627, 13633, 13649, 13669, 13679, 13681,
    13687, 13691, 13693, 13697, 13709, 13711, 13721, 13723,
    13729, 13751, 13757, 13759, 13763, 13781, 13789, 13799,
    13807, 13829, 13831, 13841, 13859, 13873, 13877, 13879,
    13883, 13901, 13903, 13907, 13913, 13921, 13931, 13933,
    13963, 13967, 13997, 13999, 14009, 14011, 14029, 14033,
    14051, 14057, 14071, 14081, 14083, 14087, 14107, 14143,
    14149, 14153, 14159, 14173, 14177, 14197, 14207, 14221,
    14243, 14249, 14251, 14281, 14293, 14303, 14321, 14323,
    14327, 14341, 14347, 14369, 14387, 14389, 14401, 14407,
    14411, 14419, 14423, 14431, 14437, 14447, 14449, 14461,
    14479, 14489, 14503, 14519, 14533, 14537, 14543, 14549,
    14551, 14557, 14561, 14563, 14591, 14593, 14621, 14627,
    14629, 14633, 14639, 14653, 14657, 14669, 14683, 14699,
    14713, 14717, 14723, 14731, 14737, 14741, 14747, 14753,
    14759, 14767, 14771, 14779, 14783, 14797, 14813, 14821,
    14827, 14831, 14843, 14851, 14867, 14869, 14879, 14887,
    14891, 14897, 14923, 14929, 14939, 14947, 14951, 14957,
    14969, 14983, 15013, 15017, 15031, 15053, 15061, 15073,
    15077, 15083, 15091, 15101, 15107, 15121, 15131, 15137,
    15139, 15149, 15161, 15173, 15187, 15193, 15199, 15217,
    15227, 15233, 15241, 15259, 15263, 15269, 15271, 15277,
    15287, 15289, 15299, 15307, 15313, 15319, 15329, 15331,
    15349, 15359, 15361, 15373, 15377, 15383, 15391, 15401,
    15413, 15427, 15439, 15443, 15451, 15461, 15467, 15473,
    15493, 15497, 15511, 15527, 15541, 15551, 15559, 15569,
    15581, 15583, 15601, 15607, 15619, 15629, 15641, 15643,
    15647, 15649, 15661, 15667, 15671, 15679, 15683, 15727,
    15731, 15733, 15737, 15739, 15749, 15761, 15767, 15773,
    15787, 15791, 15797, 15803, 15809, 15817, 15823, 15859,
    15877, 15881, 15887, 15889, 15901, 15907, 15913, 15919,
    15923, 15937, 15959, 15971, 15973, 15991, 16001, 16007,
    16033, 16057, 16061, 16063, 16067, 16069, 16073, 16087,
    16091, 16097, 16103, 16111, 16127, 16139, 16141, 16183,
    16187, 16189, 16193, 16217, 16223, 16229, 16231, 16249,
    16253, 16267, 16273, 16301, 16319, 16333, 16339, 16349,
    16361, 16363, 16369, 16381, 16411, 16417, 16421, 16427,
    16433, 16447, 16451, 16453, 16477, 16481, 16487, 16493,
    16519, 16529, 16547, 16553, 16561, 16567, 16573, 16603,
    16607, 16619, 16631, 16633, 16649, 16651, 16657, 16661,
    16673, 16691, 16693, 16699, 16703, 16729, 16741, 16747,
    16759, 16763, 16787, 16811, 16823, 16829, 16831, 16843,
    16871, 16879, 16883, 16889, 16901, 16903, 16921, 16927,
    16931, 16937, 16943, 16963, 16979, 16981, 16987, 16993,
    17011, 17021, 17027, 17029, 17033, 17041, 17047, 17053,
    17077, 17093, 17099, 17107, 17117, 17123, 17137, 17159,
    17167, 17183, 17189, 17191, 17203, 17207, 17209, 17231,
    17239, 17257, 17291, 17293, 17299, 17317, 17321, 17327,
    17333, 17341, 17351, 17359, 17377, 17383, 17387, 17389,
    17393, 17401, 17417, 17419, 17431, 17443, 17449, 17467,
    17471, 17477, 17483, 17489, 17491, 17497, 17509, 17519,
    17539, 17551, 17569, 17573, 17579, 17581, 17597, 17599,
    17609, 17623, 17627, 17657, 17659, 17669, 17681, 17683,
    17707, 17713, 17729, 17737, 17747, 17749, 17761, 17783,
    17789, 17791, 17807, 17827, 17837, 17839, 17851, 17863
     ) ;
 {$endif SB_PGPSFX_STUB}

resourcestring
  SMathOperationCanceled = 'Mathematical operation canceled';


{$ifdef SB_HAS_MEMORY_MANAGER}
procedure TLInt.Reset;
begin
	// all job is done in LCreate
end;
 {$endif}

(*
{$ifdef SB_X86ASM}
function xMUL(const A, B : LongWord) : Int64; assembler;
asm
  mul    edx
  ret
end;
{$endif}
*)


procedure LShl(var Num: PLInt);
var
  I: Integer;
begin
  if Num.Length >= MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  Num.Digits[Num.Length + 1] := 0;
  for I := Num.Length + 1 downto 2 do
    Num.Digits[I] := (Num.Digits[I] shl 1) or (Num.Digits[I - 1] shr 31);
  Num.Digits[1] := Num.Digits[1] shl 1;
  if Num.Digits[Num.Length + 1] <> 0 then
    Inc(Num.Length);
end;

procedure LShlEx(var Num: PLInt; Bits : integer);
var
  i, m, k : integer;
begin
  if Bits = 0 then Exit;

  m := Bits shr 5;
  k := Bits and $1F;

  if Num.Length + m >= MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  if k = 0 then
  begin
    for i := Num.Length downto 1 do
      Num.Digits[i + m] := Num.Digits[i];

    for i := m downto 1 do
      Num.Digits[i] := 0;

    Num.Length := Num.Length + m;
  end
  else
  begin
    Num.Digits[Num.Length + m + 1] := Num.Digits[Num.Length] shr (32 - k);

    for i := Num.Length downto 2 do
      Num.Digits[i + m] := (Num.Digits[i] shl k) or (Num.Digits[i - 1] shr (32 - k));

    Num.Digits[m + 1] := Num.Digits[1] shl k;

    for i := m downto 1 do
      Num.Digits[i] := 0;

    if Num.Digits[Num.Length + m + 1] > 0 then  
      Num.Length := Num.Length + m + 1
    else
      Num.Length := Num.Length + m;
  end;
end;

procedure LShlNum(Src, Dest: PLInt; Bits: Integer);
var
  I: LongWord;
  B, Srcc: PLInt;
  M, N: LongWord;
  Digit: LongWord;
  ByteInd, BitInd: LongWord;
begin
  M := Bits shr 5;
  N := Bits mod 32;

  if M + LongWord(Src.Length) + 1 > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  LCreate(Srcc);
  LCopy(Srcc, Src);
  B := Dest;

  for I := 1 to M + LongWord(Src.Length) + 1 do
    B.Digits[I] := 0;

  I := 0;

  while not LNull(Srcc) do
  begin
    Digit := Srcc.Digits[1] and 1;

    ByteInd := I shr 5 + M + 1;
    BitInd := I mod 32 + N;

    if BitInd >= 32 then
    begin
      BitInd := BitInd - 32;
      ByteInd := ByteInd + 1;
    end;
    B.Digits[byteind] := B.Digits[byteind] or (digit shl bitind);
    LShr(Srcc);
    Inc(I);
  end;

  B.Length := Src.Length + Integer(M) + 1;
  LTrim(B);
  LDestroy(Srcc);
end;

procedure LShr(var Num: PLInt);
var
  I: Integer;
begin
  if Num.Length >= MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  Num.Digits[Num.Length + 1] := 0;
  for I := 1 to Num.Length do
    Num.Digits[I] := (Num.Digits[I] shr 1) or (Num.Digits[I + 1] shl 31);
  if (Num.Digits[Num.Length] = 0) and (Num.Length > 1) then
    Dec(Num.Length);
end;

procedure LShrEx(var Num: PLInt; Bits : integer);
var
  i, m, k : integer;
begin
  if Bits = 0 then Exit;

  if Num.Length >= MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  m := Bits shr 5;
  k := Bits and $1F;

  if m > Num.Length then
  begin
    Num.Length := 1;
    Num.Digits[1] := 0;
    Exit;
  end;

  if k = 0 then
  begin
    for i := 1 to Num.Length - m do
      Num.Digits[i] := Num.Digits[i + m];

    Num.Length := Num.Length - m;
  end
  else
  begin
    for i := 1 to Num.Length - m - 1 do
      Num.Digits[i] := (Num.Digits[i + m + 1] shl (32 - k)) or (Num.Digits[i + m] shr k);

    Num.Digits[Num.Length - m] := Num.Digits[Num.Length] shr k;

    if Num.Digits[Num.Length - m] = 0 then
      Num.Length := Num.Length - m - 1
    else
      Num.Length := Num.Length - m;
  end;
end;

procedure LDec(var A: PLInt);
var
  One: PLInt;
begin
  LCreate(One);
  LSub(A, One, A);
  LDestroy(One);
end;

procedure LInc(var A: PLInt);
var
  One: PLInt;
begin
  LCreate(one);
  LAdd(A, One, A);
  LDestroy(One);
end;

{ only for positive numbers }
procedure LAdd(A: PLInt; B : LongWord;  C: PLInt);
var
  i : integer;
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  C.Length := A.Length;

  if A.Length = 0 then Exit;

  if A.Digits[1] > $ffffffff - B then
  begin
    C.Digits[1] := LongWord(A.Digits[1] + B);

    i := 2;
    while (i <= A.Length) and (A.Digits[i] = $ffffffff) do
    begin
      C.Digits[i] := 0;
      Inc(i);
    end;

    if (i <= A.Length) then
    begin
      C.Digits[i] := A.Digits[i] + 1;
      Inc(i);
    end
    else
    begin
      if C.Length >= MAXDIGIT then
        raise EElMathException.Create(sNumberTooLarge);
      C.Digits[i] := 1;
      Inc(C.Length);
    end;
  end
  else
  begin
    C.Digits[1] := A.Digits[1] + B;
    i := 2;
  end;

  for i := i to A.Length do
    C.Digits[i] := A.Digits[i];
end;


procedure LAdd(A, B: PLInt;  C: PLInt);
var
  I: Integer;
  Per{,
  Per1}: Integer;
  {$ifndef SB_X86ASM}
  Rs: TSBInt64;
   {$endif}
  Res: PLInt;
begin
  if (A.Length > MAXDIGIT) or (B.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  if (B.Sign = False) and (A.Sign = True) then
  begin
    B.Sign := True;
    LSub(A, B, C);
    if B <> C then B.Sign := False;
  end
  else
  if (A.Sign = False) and (B.Sign = True) then
  begin
    A.Sign := True;
    LSub(B, A, C);
    if A <> C then A.Sign := False;
  end
  else
  begin
    Res := C;
    if (A.Length < B.Length) then
    begin
      Ladd(B, A, Res);
    end
    else
    begin
      Per := 0;
//      Per1 := 0;
      Res.Sign := True;
      for I := 1 to B.Length do
      begin
        {$ifdef SB_X86ASM}
        asm
          push eax
          push ebx
          push ecx
          push edx
          mov edx, 0
          mov ecx, I
          shl ecx, 2
          mov ebx, dword ptr [A]
          mov eax, dword ptr [ebx + ecx]
          mov ebx, dword ptr [B]
          add eax, dword ptr [ebx + ecx]
          adc edx, 0
          add eax, Per
          adc edx, 0
          mov Per, edx
          {
          cmp edx, 0
          je @no_inc

          inc eax

        @no_inc:
          }
          mov ebx, dword ptr [Res]
          mov dword ptr [ebx + ecx], eax

          pop edx
          pop ecx
          pop ebx
          pop eax
        end;
         {$else}
        Rs := TSBInt64(A.Digits[I]) + TSBInt64(B.Digits[I]) + Per;

        if Rs > 4294967295 then
        begin
          Rs := Rs - 4294967296;
          Per := 1;
        end
        else
        begin
          Per := 0;
        end;

        Res.Digits[I] := Rs;
         {$endif}
      end;

      for I := B.Length + 1 to A.Length do
      begin
        {$ifdef SB_X86ASM}
        asm
          push eax
          push ebx
          push ecx
          push edx
          mov edx, 0
          mov ecx, I
          shl ecx, 2
          mov ebx, dword ptr [A]
          mov eax, dword ptr [ebx + ecx]
          //mov ebx, dword ptr [B]
          //add eax, dword ptr [ebx + ecx]
          //adc edx, 0
          add eax, Per
          adc edx, 0
          mov Per, edx
          {
          cmp edx, 0
          je @no_inc

          inc eax

        @no_inc:
          }
          mov ebx, dword ptr [Res]
          mov dword ptr [ebx + ecx], eax
          pop edx
          pop ecx
          pop ebx
          pop eax
        end;
         {$else}
        Rs := {LongInt}TSBInt64(A.Digits[I]) + Per; // 140403
        if Rs > 4294967295 then
        begin
          Rs := Rs - 4294967296;
          Per := 1;
        end
        else
        begin
          Per := 0;
        end;
        Res.Digits[I] := Rs;
         {$endif}
      end;
      if Per > 0 then
      begin
        if A.Length >= MAXDIGIT then
          raise EElMathException.Create(sNumberTooLarge);
        Res.Digits[A.Length + 1] := 1;
        Res.Length := A.Length + 1;
      end
      else
      begin
        Res.Length := A.Length;
      end;
      if (A.Sign = False) and (B.Sign = False) then
        Res.Sign := False;
    end;
  end;
end;

{ only for positive numbers, 1 - 2 = $ffffffff }
procedure LSub(A: PLInt; B : LongWord; var PTm: PLInt);
var
  i : integer;
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  PTm.Length := A.Length;

  if A.Length = 0 then Exit;

  i := 1;

  if A.Digits[1] < B then
  begin
    PTm.Digits[1] := $ffffffff - B + A.Digits[I] + 1;

    i := 2;
    while (i <= A.Length) and (A.Digits[i] = 0) do
    begin
      PTm.Digits[i] := $ffffffff;
      Inc(i);
    end;

    if (i <= A.Length) then
    begin
      PTm.Digits[i] := A.Digits[i] - 1;
      if (i = A.Length) and (PTm.Digits[i] = 0) then Dec(PTm.Length);
      Inc(i);
    end
  end
  else
  begin
    PTm.Digits[1] := A.Digits[1] - B;
    i := 2;
  end;

  for i := i to A.Length do
    PTm.Digits[i] := A.Digits[i];
end;

procedure LSub(A, B: PLInt; var PTm: PLInt);
var
  I: LongWord;
  Per:  Integer ;
  Prs: TSBInt64;
  Bb: LongWord;
  P: PLInt;
begin
  if (A.Length > MAXDIGIT) or (B.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  if (A.Sign = False) and (B.Sign = True) then
  begin
    A.Sign := True;
    LAdd(A, B, PTm);
    A.Sign := False;
    PTm.Sign := False;
    Exit;
  end;
  if (B.Sign = False) and (A.Sign = True) then
  begin
    B.Sign := True;
    LAdd(A, B, PTm);
    B.Sign := False;
    PTm.Sign := True;
    Exit;
  end;
  if (B.Sign = False) and (A.Sign = False) then
  begin
    A.Sign := True;
    B.Sign := True;
    LSub(B, A, PTm);
    if B <> PTm then B.Sign := False;
    if A <> PTm then A.Sign := False;
    Exit;
  end;
  if (LGreater(B, A) and (not LEqual(B, A))) then
  begin
    P := PTm;
    LSub(B, A, P);
    P.Sign := False;
  end
  else
  begin
    P := PTm;
    Per := 0;

    for I := 1 to A.Length do
    begin
      if Integer(I) > B.Length then
        Bb := 0
      else
        Bb := B.Digits[I];
      Prs := TSBInt64(A.Digits[I]) - TSBInt64(Bb) - Per;
      if (Prs < 0) then
      begin
        P.Digits[I] := Prs + 4294967296;
        Per := 1;
      end
      else
      begin
        P.Digits[I] := Prs;
        Per := 0;
      end;
    end;
    P.Length := A.Length;
    while (P.Digits[P.Length] = 0) and (P.Length > 1) do
      P.Length := P.Length - 1;
    P.Sign := True;
  end;

  if (A.Sign = False) and (B.Sign = False) then
    P.Sign := not P.Sign;
end;

function LGreater(A, B: PLInt): Boolean;
var
  I: Integer;
  C1, C2 : LongWord;
begin
  if (A.Length > MAXDIGIT) or (B.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  C1 := A.Length;
  C2 := B.Length;

  if C1 = C2 then
  begin
    I := C1;

    while (A.Digits[I] = B.Digits[I]) and (I > 1) do Dec(I);

    Result := A.Digits[I] > B.Digits[I];
  end
  else
    Result := C1 > C2;
end;

function LEqual(A, B: PLInt): Boolean;
var
  I: Integer;
begin
  if (A.Length > MAXDIGIT) or (B.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  if (A.Length <> B.Length) then
    result := False
  else
    if (A.Sign xor B.Sign = True) and (not LNull(A) or not LNull(B)) then
      result := False
    else
    begin
      result := True;
      for I := 1 to A.Length do
        if (A.Digits[I] <> B.Digits[I]) then
        begin
          result := False;
          Break;
        end;
    end;
end;

function LEven(A: PLInt): Boolean;
begin
  if A.Digits[1] and 1 = 0 then
    result := True
  else
    result := False;
end;

function LNull(A: PLInt): Boolean;
var
  I : integer;
begin
  if (A.Length < 1) or ((A.Length = 1) and (A.Digits[1] = 0)) then
    result := True
  else
  begin
    result := True;
    if A.Length > MAXDIGIT then
      raise EElMathException.Create(sNumberTooLarge);

    for I := 1 to A.Length do
      if A.Digits[I] <> 0 then
        result := False;
  end;
end;

procedure LZero(var A: PLInt);
begin
  A.Digits[1] := 0;
  A.Length := 1;
end;

procedure LCopy(var P: PLInt; A: PLInt);
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  SBMove(A.Digits[1], P.Digits[1], A.Length shl 2);
  P.Length := A.Length;
  P.Sign := A.Sign;
end;


procedure LShiftLeft(var A: PLInt; N: LongWord);
begin
  if A.Length + Integer(N) > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);
  SBMove(A.Digits[1], A.Digits[N + 1], A.Length shl 2);
  FillChar(A.Digits[1], N shl 2, 0);
  A.Length := A.Length + Integer(N);
end;

procedure LShiftRight(var A: PLInt; N: LongWord);
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  SBMove(A.Digits[N + 1], A.Digits[1], (A.Length - integer(N)) shl 2);
  A.Length := A.Length - integer(N);
end;

procedure LTrim(var A: PLInt);
var
  I: Integer;
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  I := A.Length;
  while (I > 0) and (A.Digits[I] = 0) do
    I := I - 1;
  A.Length := I;
end;

procedure LMult(A, B: PLInt; var Res: PLInt);
var
  P, Sum, Sum2: PLInt;
  I: Integer;
  Ptr : pointer;
begin
  if (A.Length > MAXDIGIT) or (B.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  if LNull(A) or LNull(B) then
  begin
    LZero(Res);
    Exit;
  end;
  if (LGreater(B, A) and (not LEqual(A, B))) then
  begin
    Sum := Res;
    LMult(B, A, Sum);
    Res := Sum;
  end
  else
  begin
    Sum := Res;
    New(P);
    LCreate(Sum2);
    Ptr := Sum2;
    LZero(Sum);
    LZero(P);
    LZero(Sum2);
    for I := 1 to B.Length do
    begin
      LMultSh(A, B.Digits[I], P);
      LShiftLeft(P, I - 1);
      LAdd(Sum, P, Sum2);
      LSwap(Sum, Sum2);
    end;
    Res := Sum;
    Dispose(P);
    // II 241103
    if Ptr <> Sum2 then
    begin
      LCopy(Sum2, Sum);
      LSwap(Sum2, Sum);
      Res := Sum;
    end;
    LDestroy(Sum2);
  end;

  if (A.Sign xor B.Sign = True) then
    Sum.Sign := False
  else
    Sum.Sign := True;
  LTrim(Sum);
end;

function LBitCount(A: PLInt): LongWord;
var
  D : cardinal;
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  Result := A.Length;

  while (Result > 1) and (A.Digits[Result] = 0) do
    Dec(Result);

  D := A.Digits[Result];
  Result := (Result - 1) shl 5;
  
  while (D > 0) do
  begin
    D := D shr 1;
    Inc(Result);
  end;
end;

procedure LDiv(A, B: PLInt; var C, D: PLInt);
var
  Delta: LongInt;
  I, J: LongWord;
  Tm, Tm2, Tm3, Tm4: PLInt;
begin
  if (A.Length > MAXDIGIT) or (B.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);
  if LNull(B) then
    raise EElMathException.Create(sDivisionByZero);

  Tm := C;
  Tm2 := D;
  LCreate(Tm3);
  LCreate(Tm4);
  LZero(Tm);
  LCopy(Tm2, A);

  Integer(Delta) := Integer(LBitCount(A)) - Integer(LBitCount(B));
  if Integer(Delta) < 0 then Delta := 0;

  J := Delta shr 5 + 1;
  for I := 1 to J do
    Tm.Digits[I] := 0;

  I := 1 shl (Delta mod 32);
  Tm.Length := Delta shr 5 + 1;
  while Delta >= 0 do
  begin
    LShlNum(B, Tm3, Delta);

    if not (LGreater(Tm3, Tm2)) then
    begin
      Tm.Digits[J] := Tm.Digits[J] or I;
      LSub(Tm2, Tm3, Tm4);
      LSwap(Tm4, Tm2);
    end;

    I := I shr 1;
    if (I = 0) then
    begin
      I := $80000000;
      J := J - 1;
    end;
    Delta := Delta - 1;
  end;

  if D <> Tm2 then D := Tm2;
  LDestroy(Tm3);
  LDestroy(Tm4);
end;

procedure LInit(var P: PLInt; Num: string);
var
  I, K: Integer;
  Nums: array[1..8] of Word;
  Sgn: Boolean;
begin
  if Length(Num) = 0 then
  begin
    P.Digits[1] := 0;
    P.Length := 1;
    P.Sign := true;
    Exit;
  end;
  K := 1;
  Sgn := True;

  if (Num[StringStartOffset] = '-') then
  begin
    Num := StringSubstring(Num, StringStartOffset + 1);
    Sgn := False;
  end;

  (*

  REPLACED with the code below

  {$ifndef SB_NET}
  I := Length(Num);
  while (I > 0) do
  {$else}
  I := Length(Num) - 1;
  while (I >= 0) do
  {$endif}
  begin
    Nums[1] := 0;
    Nums[2] := 0;
    Nums[3] := 0;
    Nums[4] := 0;
    Nums[5] := 0;
    Nums[6] := 0;
    Nums[7] := 0;
    Nums[8] := 0;

    Nums[1] := HexToDecDigit(Num[I]);
    {$ifndef SB_NET}
    if (I > 1) then Nums[2] := HexToDecDigit(Num[I - 1]);
    if (I > 2) then Nums[3] := HexToDecDigit(Num[I - 2]);
    if (I > 3) then Nums[4] := HexToDecDigit(Num[I - 3]);
    if (I > 4) then Nums[5] := HexToDecDigit(Num[I - 4]);
    if (I > 5) then Nums[6] := HexToDecDigit(Num[I - 5]);
    if (I > 6) then Nums[7] := HexToDecDigit(Num[I - 6]);
    if (I > 7) then Nums[8] := HexToDecDigit(Num[I - 7]);
    {$else}
    if (I > 0) then Nums[2] := HexToDecDigit(Num[I - 1]);
    if (I > 1) then Nums[3] := HexToDecDigit(Num[I - 2]);
    if (I > 2) then Nums[4] := HexToDecDigit(Num[I - 3]);
    if (I > 3) then Nums[5] := HexToDecDigit(Num[I - 4]);
    if (I > 4) then Nums[6] := HexToDecDigit(Num[I - 5]);
    if (I > 5) then Nums[7] := HexToDecDigit(Num[I - 6]);
    if (I > 6) then Nums[8] := HexToDecDigit(Num[I - 7]);
    {$endif}
  *)

  I := Length(Num) - StringStartInvOffset;
  while (I >= StringStartOffset) do
  begin
    Nums[1] := 0;
    Nums[2] := 0;
    Nums[3] := 0;
    Nums[4] := 0;
    Nums[5] := 0;
    Nums[6] := 0;
    Nums[7] := 0;
    Nums[8] := 0;

    Nums[1] := HexToDecDigit(Num[I]);
    if (I > StringStartOffset + 0) then Nums[2] := HexToDecDigit(Num[I - 1]);
    if (I > StringStartOffset + 1) then Nums[3] := HexToDecDigit(Num[I - 2]);
    if (I > StringStartOffset + 2) then Nums[4] := HexToDecDigit(Num[I - 3]);
    if (I > StringStartOffset + 3) then Nums[5] := HexToDecDigit(Num[I - 4]);
    if (I > StringStartOffset + 4) then Nums[6] := HexToDecDigit(Num[I - 5]);
    if (I > StringStartOffset + 5) then Nums[7] := HexToDecDigit(Num[I - 6]);
    if (I > StringStartOffset + 6) then Nums[8] := HexToDecDigit(Num[I - 7]);

    if K > MAXDIGIT then
      raise EElMathException.Create(sNumberTooLarge);

    P.Digits[K] := LongWord(Nums[1]) +
      LongWord(Nums[2]) shl 4 + LongWord(Nums[3]) shl 8 + LongWord(Nums[4]) shl
        12 +
      LongWord(Nums[5]) shl 16 + LongWord(Nums[6]) shl 20 + LongWord(Nums[7]) shl
        24 +
      LongWord(Nums[8]) shl 28;

    K := K + 1;
    I := I - 8;
  end;
  P.Length := K - 1;
  P.Sign := Sgn;
end;

procedure LInit(var P: PLInt; Num: LongWord);
begin
  P.Length := 1;
  P.Digits[1] := Num;
  P.Sign := True;
end;

procedure LInit(var P: PLInt; Num: Int64);
begin
  P.Sign := (Num >= 0);
  Num := Abs(Num);

  if Num <= High(LongWord) then
  begin
    P.Length := 1;
    P.Digits[1] := LongWord(Num);
  end
  else
  begin
    P.Length := 2;
    P.Digits[1] := LongWord(Num);
    P.Digits[2] := Num shr 32;
  end;
end;

procedure LCreate({$ifndef BUILDER_USED}out {$else}var {$endif} A: PLInt);
begin
  New(A);
  A.Length := 1;
  A.Digits[1] := 1;
  A.Sign := True;
end;

procedure LGenerate(var R: PLInt; Len: Integer);
var
  I: Integer;
begin
  if Len > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  for I := 1 to Len do
    R.Digits[I] := SBRndGenerate(0); //Random(4294967295);

  R.Length := Len;
  R.Sign := True;
end;

{.$hints off}
procedure LDestroy(var P: PLInt);
var X : PLInt;
begin
  if Assigned(P) then
  begin
    X := P;
    P := nil;
    //LZero(X);
    Dispose(X);
  end;
end;
{.$hints on}

function DecToHexDigit(A: Integer): Char;
begin
  if a < 10 then
    result := Chr(A + Ord('0'))
  else
    result := Chr(A - 10 + Ord('A'));
end;

function HexToDecDigit(A: Char): Integer;
begin
  A := UpCase(A);
  if (Ord(A) >= Ord('0')) and (Ord(A) <= Ord('9')) then
    result := Ord(A) - Ord('0')
  else
    if (Ord(A) >= Ord('A')) and (Ord(A) <= Ord('F')) then
      result := Ord(A) - Ord('A') + 10
    else
      Result := -1;
end;

function DecToHex(A: LongWord): string;
var
  S: array [0..7] of Char;
begin
  S[7] := DecToHexDigit(A mod 16);
  S[6] := DecToHexDigit((A shr 4) mod 16);
  S[5] := DecToHexDigit((A shr 8) mod 16);
  S[4] := DecToHexDigit((A shr 12) mod 16);
  S[3] := DecToHexDigit((A shr 16) mod 16);
  S[2] := DecToHexDigit((A shr 20) mod 16);
  S[1] := DecToHexDigit((A shr 24) mod 16);
  S[0] := DecToHexDigit((A shr 28) mod 16);
  result := S;
end;

function LToStr(A: PLInt): string;
var
  I: Integer;
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  Result := '';
  if A.Sign = False then Result := '-';
  for I := A.Length downto 1 do
  begin
    Result := Result + DecToHex(A.Digits[I]);
  end;
end;

function LToBase64(A: PLInt): string;
var
  Size, OutSize : integer;
  Buf : ByteArray;
  {$ifdef SB_UNICODE_VCL}
  OutBuf : ByteArray;
   {$endif}
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  

  Size := A.Length shl 2;
  SetLength(Buf, Size);
  LIntToPointerP(A, @Buf[0], Size);
  SetLength(Buf, Size);
  OutSize := 0;
  Base64Encode(@Buf[0], Size, nil, OutSize, false);
  {$ifndef SB_UNICODE_VCL}
  SetLength(Result, OutSize);
  Base64Encode(@Buf[0], Size, @Result[StringStartOffset], OutSize, false);
  SetLength(Result, OutSize);
   {$else}
  SetLength(OutBuf, OutSize);
  Base64Encode(@Buf[0], Size, @OutBuf[0], OutSize, false);
  SetLength(OutBuf, OutSize);
  Result := StringOfBytes(OutBuf);
   {$endif}

end;

procedure LModPower(A, E, N: PLInt; var Res: PLInt);
var
  Tmp: PLInt;
  Tm1, Tm2: PLInt;
  Ac, Ec, Nc: PLInt;
begin
  if (A.Length > MAXDIGIT) or (E.Length > MAXDIGIT) or (N.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);
  if LNull(N) then
    raise EElMathException.Create(sDivisionByZero);

  LCreate(Tm1);
  LCreate(Tm2);

  if ((E.Length = 1) and (E.Digits[1] = 1)) then
  begin
    LMod(A, N, Res);
    LDestroy(Tm1);
    LDestroy(Tm2);
    Exit;
  end;

  LCreate(Ec);
  LCreate(Tmp);

  Ac := A;
  Nc := N;
  LCopy(Ec, E);

  if (LEven(Ec)) then
  begin
    LShr(Ec);
    LModPower(Ac, Ec, Nc, Tm1);
    LMult(Tm1, Tm1, Tm2);
    LMod(Tm2, Nc, Res);
  end
  else
  begin
    LDec(Ec);
    LShr(Ec);
    LModPower(Ac, Ec, Nc, Tm1);
    LMult(Tm1, Tm1, Tmp);
    LMod(Tmp, Nc, Tm2);
    LMult(Tm2, Ac, Tm1);
    LMod(Tm1, Nc, Res);
  end;
  LDestroy(Ec);
  LDestroy(Tm1);
  LDestroy(Tm2);
  LDestroy(Tmp);
end;

procedure LGCD(B, A: PLInt; var C, D: PLInt);
var
  G: PLInt;
  X, Y: PLInt;
  U, V: PLInt;
  Ba, Bb, Bc, Bd: PLInt;
  Tm: PLInt;
  OldC, OldD : PLInt;
begin
  if (A.Length > MAXDIGIT) or (B.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);
  if LNull(A) or LNull(B) then
    raise EElMathException.Create(sDivisionByZero);

  LCreate(X);
  LCreate(Y);
  LCreate(U);
  LCreate(V);
  LCreate(Ba);
  LCreate(Bb);
  LCreate(Bc);
  LCreate(Tm);
  LCreate(OldC);
  LCreate(OldD);

  try

    Bd := OldD;
    LCopy(X, A);
    LCopy(Y, B);

    G := OldC;
    G.Length := 1;
    G.Digits[1] := 1;

    while (LEven(X) and LEven(Y)) do
    begin
      LShr(X);
      LShr(Y);
      LShl(G);
    end;

    LCopy(U, X);
    LCopy(V, Y);
    LZero(Bb);
    LZero(Bc);
    Bd.Length := 1;
    Bd.Digits[1] := 1;

    repeat

      while LEven(U) do
      begin
        LShr(U);
        if (LEven(Ba) and LEven(Bb)) then
        begin
          LShr(Ba);
          LShr(Bb);
        end
        else
        begin
          LAdd(Ba, Y, Tm);
          LSwap(Ba, Tm);
          LShr(Ba);
          LSub(Bb, X, Tm);
          LSwap(Bb, Tm);
          LShr(Bb);
        end;
      end;

      while LEven(V) do
      begin
        LShr(V);
        if (LEven(Bc) and LEven(Bd)) then
        begin
          LShr(Bc);
          LShr(Bd);
        end
        else
        begin
          LAdd(Bc, Y, Tm);
          LSwap(Bc, Tm);
          LShr(Bc);
          LSub(Bd, X, Tm);
          LSwap(Bd, Tm);
          LShr(Bd);
        end;
      end;

      if (LGreater(U, V) or LEqual(U, V)) then
      begin
        LSub(U, V, U);
        LSub(Ba, Bc, Tm);
        LSwap(Ba, Tm);
        LSub(Bb, Bd, Tm);
        LSwap(Bb, Tm);
      end
      else
      begin
        LSub(V, U, V);
        LSub(Bc, Ba, Tm);
        LSwap(Bc, Tm);
        LSub(Bd, Bb, Tm);
        LSwap(Bd, Tm);
      end;

    until LNull(U);

    LMult(G, V, Tm);
    LSwap(G, Tm);
    if G <> OldC then OldC := G;

    while (Bd.Sign = False) do
    begin
      LAdd(Bd, A, Tm);
      LSwap(Tm, Bd);
    end;

    if OldD <> Bd then OldD := Bd;

    LCopy(C, OldC);
    LCopy(D, OldD);
    
  finally
    LDestroy(OldC);
    LDestroy(OldD);
    LDestroy(Y);
    LDestroy(X);
    LDestroy(U);
    LDestroy(V);
    LDestroy(Ba);
    LDestroy(Bb);
    LDestroy(Bc);
    LDestroy(Tm);
  end;
end;

procedure LMontgomery(A, B, N: PLInt; var Res: PLInt);
var
  R, Ac, Tm: PLInt;
  I, J: Integer;
begin
  if (A.Length > MAXDIGIT) or (B.Length > MAXDIGIT) or (N.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);
  if LNull(N) then
    raise EElMathException.Create(sDivisionByZero);

  LCreate(R);
  LCreate(Ac);
  LCreate(Tm);
  LCopy(Ac, A);
  LZero(R);
  I := 0;
  while (not LNull(Ac)) do
  begin
    I := I + 1;
    if (Ac.Digits[1] mod 2) = 1 then
    begin
      LAdd(R, B, Tm);
      LSwap(Tm, R);
    end;
    if (R.Digits[1] mod 2) = 1 then
    begin
      LAdd(R, N, Tm);
      LSwap(Tm, R);
    end;
    LShr(R);
    LShr(Ac);
  end;
  if (LGreater(R, N)) then
  begin
    LSub(R, N, Tm);
    LSwap(R, Tm);
  end;

  LMod(R, N, Res);

  for J := 1 to I do
  begin
    LShl(Res);
    if (LGreater(Res, N)) then
    begin
      LSub(Res, N, Tm);
      LSwap(Res, Tm);
    end;
  end;

  LDestroy(Tm);
  LDestroy(Ac);
  LDestroy(R);
end;

{$ifdef SB_X86ASM}
procedure LSwap(var A, B: PLInt); assembler;
asm
  push EAX
  push EBX
  push ECX
  push EDX

  lea EAX, DWORD PTR [A]
  mov EBX, DWORD PTR [EAX]

  lea EDX, DWORD PTR [B]
  mov ECX, DWORD PTR [EDX]

  mov DWORD PTR [EAX], ECX
  mov DWORD PTR [EDX], EBX

  pop EDX
  pop ECX
  pop EBX
  pop EAX
end;
 {$else}
procedure LSwap(var A, B: PLInt);
var
  Tmp: PLInt;
begin
  Tmp := A;
  A := B;
  B := Tmp;
end;
 {$endif}

procedure LMod(X, N: PLInt; var Res: PLInt);
var
  Y, Z, Tm, Xc: PLInt;
begin
  if (X.Length > MAXDIGIT) or (N.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);
  if LNull(N) then
    raise EElMathException.Create(sDivisionByZero);

  LCreate(Y);
  LCreate(Z);
  LCreate(Tm);
  LCopy(Y, N);
  Xc := Res;
  LCopy(Xc, X);
  if (LGreater(Xc, N)) then
  begin
    LCopy(Z, Y);
    repeat
      LSwap(Z, Y);
      LAdd(Z, Y, Tm);
      LSwap(Tm, z);
    until not LGreater(Xc, Z);
    repeat
      if (LGreater(Xc, Y)) then
      begin
        LSub(Xc, Y, Tm);
        LSwap(Tm, Xc);
      end
      else if LEqual(Xc, Y) then
        LZero(Xc);
      LSwap(Y, Z);
      LSub(Y, Z, Tm);
      LSwap(Tm, Y);
    until LGreater(Y, Z);
  end;
  Res := Xc;
  LDestroy(Y);
  LDestroy(Z);
  LDestroy(Tm);
end;

{$ifndef SB_MSSQL}

(* Barret realization *)

procedure LBAddPowB(Src, Dest: PLInt; Bases: Cardinal);
var
  I, Count: Cardinal;
  Value: TSBint64;
begin
  if (Src.Length > MAXDIGIT) or (Bases >= MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  Count := Src.Length;

  I := 1;
  while I <= Bases do
  begin
    Dest.Digits[I] := Src.Digits[I];
    Inc(I);
  end;

  TSuperBaseRec(value).Hi := 1;

  while (I <= Count) do
  begin
    Value := Cardinal(Src.Digits[I]) + TSuperBaseRec(Value).Hi;
    Dest.Digits[I] := TSuperBaseRec(Value).Lo;
    Inc(I);
  end;

  Dest.Length := Count;
  if Integer(Bases) >= Src.Length then
  begin
    for I := Src.Length + 1 to Bases do
    begin
      Dest.Length := Dest.Length + 1;
      Dest.Digits[I] := 0;
    end;
    Dest.Length := Dest.Length + 1;
    Dest.Digits[Dest.Length] := 1;
  end;
end;

procedure LBM(SrcMod, Dest: PLInt; Bits: Cardinal);
var
  TmpB, TmpMod: PLInt;
begin
  LCreate(TmpB);
  LCreate(TmpMod);
  LZero(TmpB);
  LBAddPowB(TmpB, TmpB, ((Bits + 32 - 1) shr 5) shl 1);
  LDiv(TmpB, SrcMod, Dest, TmpMod);
  LDestroy(TmpB);
  LDestroy(TmpMod);
end;

procedure LBDivPowB(Src, Dest: PLInt; Bases: Cardinal);
var
  I: LongWord;
begin
  if Src.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  for I := 1 to Src.Length - Integer(Bases) do
  begin
    Dest.Digits[I] := Src.Digits[I + Bases];
  end;
  Dest.Length := Src.Length - Integer(Bases);
end;

procedure LBModPowB(Src, Dest: PLInt; Bases: Cardinal);
var
  I: Integer;
begin
  if Src.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  for I := 1 to Min(Bases, Src.Length) do
  begin
    Dest.Digits[I] := Src.Digits[I];
  end;
  Dest.Length := Bases;

  if Dest.Length > Src.Length then Dest.Length := Src.Length;
end;

procedure LBMul(SrcA, SrcB, Dest: PLInt; FromBases, ToBases: Cardinal);
var
  A, B: Cardinal;
  Value, Mult: Int64;
  CurrDest, DestA, DestB, CurrB, ASrc: ^LongWord;
  I: LongWord;
  Count: LongWord;
begin
  if (SrcA.Length > MAXDIGIT) or (SrcB.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  LZero(Dest);
  Count := SrcA.Length;
  if Integer(ToBases) > SrcA.Length + SrcB.Length then
    ToBases := SrcA.Length + SrcB.Length;

  for I := Min(Min(SrcA.Length, SrcB.Length), Dest.Length) + 1 to MAXDIGIT do
  begin
    if Integer(I) > SrcA.Length then SrcA.Digits[I] := 0;
    if Integer(I) > SrcB.Length then SrcB.Digits[I] := 0;
    if Integer(I) > Dest.Length then Dest.Digits[I] := 0;
  end;

  SrcA.Digits[SrcA.Length + 1] := 0;
  SrcB.Digits[SrcB.Length + 1] := 0;
  Dest.Digits[Dest.Length + 1] := 0;

  if FromBases > 0 then
    Dec(FromBases);
  Dec(ToBases);

  ASrc := @SrcA.Digits;
  DestA := @Dest.Digits;
  for A := FromBases to ToBases do
  begin
    DestB := DestA;
    CurrB := @SrcB.Digits;
    if (ASrc^ <> 0) then
      for B := FromBases to ToBases do
      begin
        CurrDest := DestB;
        if (CurrB^ <> 0) then
        begin
          Mult := Int64(ASrc^) * CurrB^;
          Value := Int64(CurrDest^) + TSuperBaseRec(Mult).Lo;
          CurrDest^ := TSuperBaseRec(Value).Lo;
          Value := TSuperBaseRec(Value).Hi + TSuperBaseRec(Mult).Hi;
          while Value <> 0 do
          begin
            Inc(CurrDest);
            Value := CurrDest^ + Value;
            CurrDest^ := TSuperBaseRec(Value).Lo;
            Value := TSuperBaseRec(Value).Hi;
          end;
        end;
        Inc(CurrB);
        Inc(DestB);
      end;
    Inc(ASrc);
    Inc(DestA);
  end;
  Dest.Length := (ToBases - FromBases + 1) shl 1;
  if Dest.Length > Integer(Count) + SrcB.Length + 1 then
    Dest.Length := Integer(Count) + SrcB.Length + 1;

  LTrim(Dest);
end;

threadvar
  Q1, R1, R2: PLInt;

procedure LBMod(Src, SrcMod, SrcM: PLInt; var Dest: PLInt; Bits: Cardinal);
var
  Count, Bases: Cardinal;
{  Tmp : PLInt;}
begin
  if (Src.Length > MAXDIGIT) or (SrcMod.Length > MAXDIGIT) or (SrcM.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

{  LCreate (Tmp);}
  Count := MAXDIGIT;
  Bases := (Bits + 32 - 1) shr 5;

{$ifdef NET_CF}
  if not SlotsAllocated then
  begin
    ss_Q1 := Thread.AllocateDataSlot();
    ss_R1 := Thread.AllocateDataSlot();
    ss_R2 := Thread.AllocateDataSlot();
    SlotsAllocated := true;
  end;

  Q1:= PLInt(Thread.GetData(ss_Q1));
  R1:= PLInt(Thread.GetData(ss_R1));
  R2:= PLInt(Thread.GetData(ss_R2));
 {$endif}

  if Q1 = nil then
  begin
    LCreate(Q1);
    {$ifdef NET_CF}
    Thread.SetData(SS_Q1, Q1);
     {$endif}
  end;
  if R1 = nil then
  begin
    LCreate(R1);
    {$ifdef NET_CF}
    Thread.SetData(SS_R1, R1);
     {$endif}
  end;
  if R2 = nil then
  begin
    LCreate(R2);
    {$ifdef NET_CF}
    Thread.SetData(SS_R2, R2);
     {$endif}
  end;
  LZero(R1);
  LZero(R2);
  LZero(Q1);

  LBDivPowB(Src, R1, Bases - 1);
  LBMul(R1, SrcM, Q1, Bases + 1, Count);
  LBDivPowB(Q1, Q1, Bases + 1);

  LBModPowB(Src, R1, Bases + 1);
  LBMul(Q1, SrcMod, R2, 0, Bases + 1);
  LBModPowB(R2, R2, Bases + 1);

  LSub(R1, R2, Dest);
  if Dest.Sign = False then
  begin
    Dest.Sign := True;
    LBAddPowB(Dest, Dest, Bases + 1);
  end;

  LSub(Dest, SrcMod, Q1);
  if Q1.Sign = True then
  begin
  //  LCopy (Dest, q1);
    LSwap(Dest, q1);
    Q1.Sign := True;
  end;
  while (Q1.Sign = True) do
  begin
    LSub(Dest, SrcMod, Q1);
    LSwap(Dest, Q1);
  end;
  {$ifdef NET_CF}
  Thread.SetData(SS_Q1, Q1);
  Thread.SetData(SS_R1, R1);
  Thread.SetData(SS_R2, R2);
   {$endif}
end;

procedure LBPowMod(SrcA, SrcB, SrcMod: PLInt; var Dest: PLInt; ModInv: PLInt);
var
  Bit, ModBit: Integer;
  Bits: LongWord;
  Temp: PLInt;
  Ind: Integer;
begin
  if (SrcA.Length > MAXDIGIT) or (SrcMod.Length > MAXDIGIT) or (SrcB.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  LCreate(Temp);
  Bit := LBitCount(SrcB) - 1;

  if Bit = 0 then
  begin
    Dest.Digits[1] := 1;
    Dest.Length := 1;
    Exit;
  end;

  Dec(Bit);
  Ind := 1 + Bit shr 5;

  Bits := 1 shl (Bit mod 32);
  LCopy(Dest, SrcA);

  ModBit := LBitCount(SrcMod);

  LBM(SrcMod, ModInv, ModBit);

  while Bit >= 0 do
  begin
    LMult(Dest, Dest, Temp);
    LBMod(Temp, SrcMod, ModInv, Dest, ModBit);

    if (SrcB.Digits[ind] and Bits) <> 0 then
    begin
      LMult(Dest, SrcA, Temp);
      LBMod(Temp, SrcMod, ModInv, Dest, ModBit);
    end;
    if (Bit mod 32) = 0 then
    begin
      Bits := $80000000;
      Ind := Ind - 1;
    end
    else
      Bits := Bits shr 1;
    Dec(Bit);
  end;

  while Dest.Sign = False do
  begin
    LAdd(Dest, SrcMod, Temp);
    LSwap(Temp, Dest);
  end;
  LDestroy(Temp);
end;

 {$endif}

(* Montgomery functions *)

procedure LShrNum(X: PLInt; var Res: PLInt; Bits: Cardinal);
var
  I: LongWord;
begin
  if X.Length >= MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  X.Digits[X.Length + 1] := 0;
  for I := 1 to X.Length - Integer(Bits shr 5) do
  begin
    Res.Digits[I] := (X.Digits[I + Bits shr 5] shr (Bits and $1F{mod 32})) or
      ((X.Digits[I + Bits shr 5 + 1] and (1 shl (Bits and $1F{mod 32}) - 1)) shl (32 -
      Bits and $1F));
  end;
  Res.Length := X.Length - Integer(Bits) div 32;
  while (Res.Digits[Res.Length] = 0) and (Res.Length > 1) do
    Dec(Res.Length);
end;

function LGetBit(A: PLInt; Bit: Cardinal): Integer;
begin
  Result := (A.Digits[(Bit - 1) shr 5 + 1] shr ((Bit - 1) and $1F{(Bit - 1) mod 32})) and 1;
end;

procedure LMMul(A, B, N: PLInt; var Res: PLInt);
var
  T, Tmp, Tmp2, Tmp3: PLInt;
  I: Cardinal;
  M, N0: TSBInt64;
begin
  if (A.Length > MAXDIGIT) or (B.Length > MAXDIGIT) or (N.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  LCreate(Tmp);
  LCreate(Tmp2);
  LCreate(Tmp3);
  T := Res;

  Tmp.Digits[1] := N.Digits[1];
  LInit(Tmp2, '100000000');
  LGCD(Tmp, Tmp2, T, Tmp3);
  N0 := (1 shl 32) - Tmp3.Digits[1] - 1;

  T.Digits[1] := 0;
  T.Length := 1;
  for I := 1 to A.Length do
  begin
    Tmp.Digits[1] := A.Digits[I];
    Tmp.Length := 1;
    LMultSh(Tmp, B.Digits[1], Tmp2);
    Tmp.Digits[1] := T.Digits[1];
    LAdd(Tmp2, Tmp, Tmp3);
    LMultSh(Tmp3, N0, Tmp);
    M := Tmp.Digits[1];

    LMultSh(B, A.Digits[I], Tmp);
    LMultSh(N, M, Tmp2);
    LAdd(T, Tmp, Tmp3);
    LAdd(Tmp3, Tmp2, Tmp);
    LShrNum(Tmp, T, 32);
  end;
  while (LGreater(T, N)) do
  begin
    LSub(T, N, Tmp);
    LSwap(Tmp, T);
  end;

  Res := T;
  LDestroy(Tmp);
  LDestroy(Tmp2);
  LDestroy(Tmp3);
end;


(* old version
procedure LMultSh(A: PLInt; B: LongWord; {$ifndef SB_VCL}var{$endif} Res: PLInt);
var
  I: Integer;
  Per : LongWord;
  {$ifndef SB_X86ASM}
  Tm : TSBInt64;
  {$endif}
  {$ifdef SB_VCL}
//  bb : LongWord;
  {$endif}
begin
  Per := 0;
  for I := 1 to A.Length do
  begin
    {$ifdef SB_X86ASM}
    asm
      push eax
      push ebx
      push ecx
      push edx
      mov ecx, I
      shl ecx, 2
      mov ebx, dword ptr [A]
      mov eax, dword ptr [ebx + ecx]

      // load parameters for multiplication
      //mov eax, bb
      mov edx, B
      mul edx

      // result is now in EAX:EDX

      // add PER
      add eax, Per
      adc edx, 0

      // save result to Tm
      //mov dword ptr [TM], EAX
      //mov dword ptr [TM + 4], EDX

      // check high DWORD of TM
      //cmp EDX, 0
      //je @empty_per

      // carry (PER) required
      //@set_per:
      mov Per, EDX
      // set lower value of Per
      //mov dword ptr [TM1 + 4], 0
      //jmp @ne_per

      //@empty_per:
      //mov Per, 0

      //@ne_per:

      //mov BB, EAX

      mov ebx, dword ptr [Res]
      mov dword ptr [ebx + ecx], eax
      pop edx
      pop ecx
      pop ebx
      pop eax
    end;
    // Res.Digits[I] := BB;
    {$else}
    Tm := TSBInt64(A.Digits[I]) * TSBInt64(B) + TSBInt64(Per);
    if (Tm > 4294967295) or (Tm < 0) then
    begin
      Per := TSBInt64(Tm) shr 32;
      Tm := TSBInt64(Tm) and TSBInt64($FFFFFFFF);
    end
    else
      Per := 0;
    Res.Digits[I] := Tm;
    {$endif}
  end;
  if Per <> 0 then
  begin
    Res.Digits[A.Length + 1] := Per;
    Res.Length := A.Length + 1;
  end
  else
    Res.Length := A.Length;

  I := Res.Length;
  while (Res.Digits[I] = 0) and (I > 1) do
    Dec(I);
  Res.Length := I;
end; *)


procedure LMultSh(A: PLInt; B: LongWord;  Res: PLInt);
var
  I: Integer;
  Per : LongWord;
  {$ifndef SB_X86ASM}
  Tm : TSBInt64;
   {$endif}
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  Per := 0;
  {$ifdef SB_X86ASM}
  asm
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    { ebx-> cycle counter, esi-> source 32bit, edi-> destination 32bit }

    mov ebx, dword ptr [A]
    mov ebx, dword ptr [ebx]

    test ebx, ebx
    jz @cycle_end

    mov esi, dword ptr [A]
    add esi, 4
    mov edi, dword ptr [Res]
    add edi, 4
    
    mov ecx, B

    @cycle_start:

    mov eax, dword ptr [esi]
    mul ecx

    add eax, Per
    adc edx, 0

    mov Per, edx
    mov dword ptr [edi], eax

    add edi, 4
    add esi, 4
    dec ebx

    jnz @cycle_start

    @cycle_end:

    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
  end;
   {$else}
  for I := 1 to A.Length do
  begin
    Tm := TSBInt64(A.Digits[I]) * TSBInt64(B) + TSBInt64(Per);
    if (Tm > 4294967295) or (Tm < 0) then
    begin
      Per := TSBInt64(Tm) shr 32;
      Tm := TSBInt64(Tm) and TSBInt64($FFFFFFFF);
    end
    else
      Per := 0;
    Res.Digits[I] := Tm;
  end;
   {$endif}
  if Per <> 0 then
  begin
    if A.Length >= MAXDIGIT then
      raise EElMathException.Create(sNumberTooLarge);

    Res.Digits[A.Length + 1] := Per;
    Res.Length := A.Length + 1;
  end
  else
    Res.Length := A.Length;

  I := Res.Length;
  while (Res.Digits[I] = 0) and (I > 1) do
    Dec(I);
  Res.Length := I;
end;


procedure LDivSh(A: PLInt; B: LongWord; Q, R: PLInt);
var
  Per, T: TSBInt64;
  N: Integer;
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);
  if B = 0 then
    raise EElMathException.Create(sDivisionByZero);

  Q.Length := A.Length;
  Per := 0;
  for N := A.Length downto 1 do
  begin
    T := TSBInt64(A.Digits[n]) + TSBInt64(4294967296) * Per;
    Q.Digits[N] := T div B;
    Per := T mod B;
  end;
  LTrim(Q);
  R.Digits[1] := Per;
  R.Length := 1;
end;

function LBitCount2(N : PLInt) : integer;
var
  A : cardinal;
begin
  if N.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  LTrim(N);
  Result := (N.Length - 1) * 32;
  A := N.Digits[N.Length];
  while A > 0 do
  begin
    A := A shr 1;
    Inc(Result);
  end;
end;

procedure LAddSh(A : PLInt; N : longword;   R : PLInt);
var
  I : integer;
  Per : cardinal;
  {$ifndef SB_X86ASM}
  T : TSBInt64;
   {$endif}
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

{$ifdef SB_X86ASM}
  asm
    push eax
    push ebx
    push ecx
    push edx

    mov edx, 0
    mov ebx, dword ptr [A]
    mov eax, dword ptr [ebx + 4]
    add eax, dword ptr [N]
    adc edx, 0
    mov Per, edx

    mov ebx, dword ptr [R]
    //mov ebx, dword ptr [ebx]
    mov dword ptr [ebx + 4], eax
    pop edx
    pop ecx
    pop ebx
    pop eax
  end;
  (*
  T := TSBInt64(A.Digits[1]) + TSBInt64(N);
  if T > 4294967295 then
  begin
    T := T - 4294967296;
    Per := 1;
  end
  else
    Per := 0;
  R.Digits[1] := T;
  *)
  for I := 2 to A.Length do
  begin

    asm
      push eax
      push ebx
      push ecx
      push edx
      mov edx, 0
      mov ecx, I
      shl ecx, 2

      mov ebx, dword ptr [A]
      mov eax, dword ptr [ebx + ecx]
      add eax, Per
      adc edx, 0
      mov Per, edx

      mov ebx, dword ptr [R]
      //mov ebx, dword ptr [ebx]
      mov dword ptr [ebx + ecx], eax
      pop edx
      pop ecx
      pop ebx
      pop edx
    end;

    (*
    T := TSBInt64(A.Digits[I]) + TSBInt64(Per);
    if T > 4294967295 then
    begin
      T := T - 4294967296;
      Per := 1;
    end
    else
      Per := 0;
    R.Digits[I] := T;
    *)
  end;
  if Per > 0 then
  begin
    if A.Length >= MAXDIGIT then
      raise EElMathException.Create(sNumberTooLarge);

    R.Digits[A.Length + 1] := Per;
    R.Length := A.Length + 1;
  end
  else
    R.Length := A.Length;

 {$else}
  T := TSBInt64(A.Digits[1]) + TSBInt64(N);
  if T > 4294967295 then
  begin
    T := T - 4294967296;
    Per := 1;
  end
  else
    Per := 0;
  R.Digits[1] := T;
  for I := 2 to A.Length do
  begin
    T := TSBInt64(A.Digits[I]) + TSBInt64(Per);
    if T > 4294967295 then
    begin
      T := T - 4294967296;
      Per := 1;
    end
    else
      Per := 0;
    R.Digits[I] := T;
  end;
  if Per > 0 then
  begin
    if A.Length >= MAXDIGIT then
      raise EElMathException.Create(sNumberTooLarge);

    R.Digits[A.Length + 1] := Per;
    R.Length := A.Length + 1;
  end
  else
    R.Length := A.Length;
 {$endif}
end;

procedure LMultShSh(A, B : cardinal;  Dest : PLInt);
{.$ifdef SB_NET}
var
  T : TSBInt64;
{.$endif}
begin
  {$ifdef SB_X86ASM}
  asm
    push eax
    push ebx
    push ecx
    push edx
    mov eax, A
    mov edx, B
    mul edx
    mov dword ptr [T], EAX
    mov dword ptr [T + 4], EDX

    mov EBX, dword ptr [Dest]
    //mov EBX, dword ptr [EBX]

    // check high DWORD of TM
    cmp EDX, 0
    je @empty_per

  @set_per:
    mov dword ptr [EBX], 2
    mov dword ptr [EBX + 4 * 2], EDX
    mov dword ptr [EBX + 4 * 1], EAX

    jmp @ne_per

  @empty_per:
    mov dword ptr [EBX], 1
    mov dword ptr [EBX + 4 * 2], 0
    mov dword ptr [EBX + 4 * 1], EAX

  @ne_per:
    pop edx
    pop ecx
    pop ebx
    pop eax

  end;

  (*
  // DO NOT REMOVE
  //if T <> TSBInt64(A) * TSBInt64(B) then
    T := TSBInt64(A) * TSBInt64(B);

  if (T > 4294967295) or (T < 0) then
  begin
    Dest.Length := 2;
    Dest.Digits[2] := TSBInt64(T) shr 32;
    Dest.Digits[1] := TSBInt64(T) and TSBInt64($FFFFFFFF);
  end
  else
  begin
    Dest.Length := 1;
    Dest.Digits[1] := T;
  end;
  *)
   {$else}
  T := TSBInt64(A) * TSBInt64(B);
  if (T > 4294967295) or (T < 0) then
  begin
    Dest.Length := 2;
    Dest.Digits[2] := TSBInt64(T) shr 32;
    Dest.Digits[1] := TSBInt64(T) and TSBInt64($FFFFFFFF);
  end
  else
  begin
    Dest.Length := 1;
    Dest.Digits[1] := T;
  end;
   {$endif}
end;


(*
// replaced by LMMontgomeryMul
procedure LMMulN0Ex(A, B, N: PLInt; var Res: PLInt; N0: Cardinal;
  var Tmp1, Tmp2, Tmp3 : PLInt);
var
  T: PLInt;
  I: Cardinal;
begin
  T := Res;
  T.Digits[1] := 0;
  T.Length := 1;
  while A.Length < N.Length do
  begin
    Inc(A.Length);
    A.Digits[A.Length] := 0;
  end;
  for I := 1 to A.Length do
  begin
    LMultShSh(A.Digits[I], B.Digits[1], Tmp2);
    LAddSh(Tmp2, T.Digits[1], Tmp3);
    LMultSh(Tmp3, N0, Tmp1);
    LMultSh(N, Tmp1.Digits[1], Tmp2);
    LMultSh(B, A.Digits[I], Tmp1);
    LAdd(T, Tmp1, Tmp3);
    LAdd(Tmp3, Tmp2, Tmp1);
    LShiftRight(Tmp1, 1);
    LSwap(Tmp1, T);
  end;
  while (LGreater(T, N)) do
  begin
    LSub(T, N, Tmp1);
    LSwap(Tmp1, T);
  end;
  Res := T;
end;

// deprecated
{procedure LMModPowerEven(X, E, N : PLInt; var Res : PLint);
var
  T1, T2 : PLInt;
  Power : integer;
begin
  LCreate(T1);
  LCreate(T2);
  LCopy(T1, E);
  Power := 0;
  while LEven(T1) and (not LNull(T1)) do
  begin
    Inc(Power);
    LShr(T1);
  end;
  if not LNull(T1) then
    LMModPowerOld(X, T1, N, T2)
  else
    LInit(T2, '00000001');
  while Power > 0 do
  begin
    LMult(T2, T2, T1);
    LModEx(T1, N, T2);
    Dec(Power);
  end;
  LCopy(Res, T2);
  LDestroy(T1);
  LDestroy(T2);
end;}

// Old version
procedure LMModPowerOld(X, E, N: PLInt; var Res: PLInt; ProgressFunc : TSBMathProgressFunc {$ifndef SB_NET}={$else}:={$endif} nil;
  Data : {$ifdef SB_VCL}pointer{$else}{$ifdef SB_JAVA}TObject{$else}System.Object{$endif}{$endif} {$ifndef SB_NET}={$else}:={$endif} nil; RaiseExceptionOnCancel : boolean {$ifndef SB_NET}={$else}:={$endif} false);
var
  Tm, Xinv, Yinv: PLInt;
  I, Rs, Bitsinr: Integer;
  Tmp1, Tmp2, Tmp3: PLInt;
  N0: Cardinal;
  {TT,} T1, T2, T3 : PLInt; // NO 12/12/04
begin
  {if LEven(E) then
  begin
    LMModPowerEven(X, E, N, Res);
    Exit;
  end;}

  LCreate(Xinv);
  LCreate(Yinv);
  LCreate(Tm);
  LCreate(Tmp1);
  LCreate(Tmp2);
  LCreate(Tmp3);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  try
    Rs := LBitCount(E);   // II 25/03/2003
    while E.Length < N.Length do
    begin
      Inc(E.Length);
      E.Digits[E.Length] := 0;
    end;
    E.Digits[E.Length + 1] := 0;
    //  Rs := LBitCount(E); // II 25/03/2003

    //Bitsinr := E.Length * 32;
    Bitsinr := E.Length shl 5;

    Tmp1.Digits[1] := N.Digits[1];
    LShiftLeft(Tmp2, 1);
    LGCD(Tmp1, Tmp2, Tm, Tmp3);
    N0 := 4294967295 - Tmp3.Digits[1] + 1;

    LShlNum(Yinv, Xinv, Bitsinr);
    LMod(Xinv, N, Yinv);
    LShlNum(X, Tm, Bitsinr);
    LMod(Tm, N, Xinv);

    for I := Rs downto 1 do
    begin
      if MathOperationCanceled(ProgressFunc, Data) then
      begin
        if RaiseExceptionOnCancel then
          raise EElMathException.Create(SMathOperationCanceled)
        else
          Exit;
      end;
      LMMulN0Ex(Yinv, Yinv, N, Tm, N0, T1, T2, T3);
      LSwap(Tm, Yinv);
      if LGetBit(E, I) = 1 then
      begin
        LMMulN0Ex(Yinv, Xinv, N, Tm, N0, T1, T2, T3);
        LSwap(Tm, Yinv);
      end;
    end;

    Xinv.Digits[1] := 1;
    Xinv.Length := 1;
    LMMulN0Ex(Yinv, Xinv, N, Res, N0, T1, T2, T3);
    //TT := Res; // NO 12/12/04
    LTrim(E);
  finally
    LDestroy(Xinv);
    LDestroy(Yinv);
    LDestroy(Tm);
    LDestroy(Tmp1);
    LDestroy(Tmp2);
    LDestroy(Tmp3);
    LDestroy(T1);
    LDestroy(T2);
    LDestroy(T3);
  end;
end; *)


{$ifndef SB_X86ASM}

procedure LMMontgomeryMul(X, Y, M : PLInt; var A : PLInt; N0 : cardinal; R : integer);
var
  i, j : integer;
  u, c1, c2, y1, xi : cardinal;
  m1, m2, s : TSBInt64;
begin
  if (X.Length > MAXDIGIT) or (Y.Length > MAXDIGIT) or (M.Length > MAXDIGIT) or (R >= MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);
  if LNull(M) then
    raise EElMathException.Create(sDivisionByZero);

  for i := 1 to R + 1 do A.Digits[i] := 0;
  y1 := Y.Digits[1];

  for i := 1 to R do
  begin
    xi := X.Digits[i];
    u := (A.Digits[1] + xi * y1) * N0;
    c1 := 0;
    c2 := 0;

    m1 := TSBInt64(xi) * TSBInt64(Y.Digits[1]);
    m2 := TSBInt64(u) * TSBInt64(M.Digits[1]);

    s := m1 and $ffffffff + m2 and $ffffffff + TSBInt64(A.Digits[1]) + TSBInt64(c2);
    s := s shr 32 + m1 shr 32 + m2 shr 32 + TSBInt64(c1);
    c2 := cardinal(s);
    c1 := cardinal(s shr 32);

    for j := 2 to R do
    begin
      m1 := TSBInt64(xi) * TSBInt64(Y.Digits[j]);
      m2 := TSBInt64(u) * TSBInt64(M.Digits[j]);

      s := m1 and $ffffffff + m2 and $ffffffff + TSBInt64(A.Digits[j]) + TSBInt64(c2);
      A.Digits[j - 1] := cardinal(s);
      s := s shr 32 + m1 shr 32 + m2 shr 32 + TSBInt64(c1);
      c2 := cardinal(s);
      c1 := cardinal(s shr 32);
    end;

    s := TSBInt64(A.Digits[R + 1]) + TSBInt64(c2);
    A.Digits[R] := cardinal(s);
    s := s shr 32 + TSBInt64(c1);
    A.Digits[R + 1] := cardinal(s);
  end;

  A.Length := R + 1;
  LTrim(A);

  if LGreater(A, M) then
    LSub(A, M, A);

  A.Length := R;
end;

 {$else}

procedure LMMontgomeryMul(X, Y, M : PLInt; var A : PLInt; N0 : cardinal; R : integer);
var
  i, j : integer;
  c1, c2 : cardinal;
  m1, m2 : Int64;
  xptr, mptr : cardinal;
begin
  if (X.Length > MAXDIGIT) or (Y.Length > MAXDIGIT) or (M.Length > MAXDIGIT) or (R >= MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);
  if LNull(M) then
    raise EElMathException.Create(sDivisionByZero);

  asm
    push eax
    push ebx
    push ecx
    push edx
    push edi
    push esi

    { xptr -> X.Digits[i], 4 will be added in cycle }
    mov eax, dword ptr [X]
    mov xptr, eax
    { edi -> A.Digits[1]}
    mov edi, dword ptr [A]
    mov edi, [edi]
    add edi, 4
    { esi -> Y.Digits[1]}
    mov esi, dword ptr [Y]
    add esi, 4
    { mptr -> M.Digits[1]}
    mov eax, dword ptr [M]
    add eax, 4
    mov mptr, eax

    { cleaning the soul of A }
    mov ecx, R
    mov i, ecx
    inc ecx
    mov ebx, edi
    xor eax, eax

    rep stosd
    mov edi, ebx

    { outer cycle }
    @i_cycle:

    add xptr, 4

    { ebx <- X.Digits[i] (xi)}
    mov eax, [xptr]
    mov eax, [eax]
    mov ebx, eax { saving xi in ebx }

    { ecx <- (A.Digits[1] + xi * Y.Digits[1]) * N0; (u) }
    mul dword ptr [esi]
    add eax, [edi]
    mul N0
    mov ecx, eax

    { c1 <- 0; c2 <- 0 }
    xor eax, eax
    mov c1, eax
    mov c2, eax

    push esi
    push edi
    push mptr

    { inner cycle }

    mov eax, R
    mov j, eax

    @j_cycle:

    { m1 <- xi * Y.Digits[j]}
    mov eax, [esi]
    mul ebx

    mov dword ptr [m1], eax
    mov dword ptr [m1 + 4], edx

    { u * M.Digits[j] }
    mov eax, [mptr]
    mov eax, [eax]
    mul ecx

    { [m2+4] <- dx }
    mov dword ptr [m2 + 4], edx
    xor edx, edx
    { edx:eax <- m2 and $ffffffff + m1 and $ffffffff}
    add eax, dword ptr [m1]
    adc edx, 0
    { edx:eax <- + A.Digits[j] + c2}
    add eax, [edi]
    adc edx, 0
    add eax, c2
    adc edx, 0

    { A.Digits[j - 1] <- eax}
    sub edi, 4
    mov [edi], eax // dirty hijack - on first iteration the A.Length is set

    { eax <- s shr 32, edx <- 0}
    mov eax, edx
    xor edx, edx
    { eax <- + m1 shr 32 + m2 shr 32 + c1}
    add eax, dword ptr [m1 + 4]
    adc edx, 0
    add eax, dword ptr [m2 + 4]
    adc edx, 0
    add eax, c1
    adc edx, 0
    mov c2, eax
    mov c1, edx

    { incrementing indexes }
    add edi, 8
    add mptr, 4
    add esi, 4

    dec j
    jnz @j_cycle

    { edx:eax <- A.Digits[R + 1] + c2 }
    xor edx, edx
    mov eax, [edi]
    add eax, c2
    adc edx, 0
    { edx <- edx + c1}
    add edx, c1
    { A.Digits[R + 1] <- edx }
    mov [edi], edx
    sub edi, 4
    mov [edi], eax

    pop mptr
    pop edi
    pop esi

    dec i
    jnz @i_cycle

    pop esi
    pop edi
    pop edx
    pop ecx
    pop ebx
    pop eax
  end;

  A.Length := R + 1;
  LTrim(A);

  if LGreater(A, M) then
    LSub(A, M, A);

  A.Length := R;
end;
 {$endif}

procedure LMModPower(X, E, N: PLInt; var Res: PLInt;
  ProgressFunc : TSBMathProgressFunc  =  nil;
  Data :  pointer   =  nil;
  RaiseExceptionOnCancel : boolean  =  false);
var
  i, RWords : integer;
  N0 : cardinal;
  R, A, XR, Tmp : PLInt;
begin
  if (X.Length > MAXDIGIT) or (E.Length > MAXDIGIT) or (N.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);
  if LNull(N) then
    raise EElMathException.Create(sDivisionByZero);

  LCreate(R);
  LCreate(A);
  LCreate(Tmp);
  LCreate(XR);

  if LEven(N) then Exit;

  { N0 = -N[0]^-1 mod 2^32 }
  R.Length := 2;
  R.Digits[1] := 0;
  R.Digits[2] := 1;
  A.Digits[1] := N.Digits[1];
  LGCD(A, R, XR, Tmp);
  N0 := $ffffffff - Tmp.Digits[1] + 1;

  { R = WordSize^N.Length }
  RWords := N.Length;
  R.Length := RWords + 1;
  R.Digits[R.Length] := 1;
  for i := 1 to RWords do R.Digits[i] := 0;
  for i := X.Length + 1 to RWords do X.Digits[i] := 0;

  { A := R mod N }
  LModEx(R, N, A);

  { XR := Mont(X, R^2 mod N) = XR mod N }
  LMult(A, X, Tmp);
  LModEx(Tmp, N, XR);

  for i := XR.Length + 1 to RWords do
    XR.Digits[i] := 0;
  XR.Length := RWords;

  LCopy(A, XR); // after first iteration always A = XR mod M

  for i := LBitCount(E) - 1 downto 1 do
  begin
    if MathOperationCanceled(ProgressFunc, Data) then
      begin
        if RaiseExceptionOnCancel then
          raise EElMathException.Create(SMathOperationCanceled)
        else
          Exit;
      end;

    // possible optimization - implement squaring, not multiplying algo
    LMMontgomeryMul(A, A, N, Tmp, N0, RWords);

    if LGetBit(E, i) = 1 then
      LMMontgomeryMul(Tmp, XR, N, A, N0, RWords)
    else
      LSwap(A, Tmp);
  end;

  Tmp.Length := 1;
  Tmp.Digits[1] := 1;
  for i := 2 to RWords do Tmp.Digits[i] := 0;
  LMMontgomeryMul(A, Tmp, N, Res, N0, RWords);

  LTrim(Res);

  LDestroy(R);
  LDestroy(A);
  LDestroy(Tmp);
  LDestroy(XR);
end;

(* Prime generation *)

function LIsPrime(P: PLInt;
  ProgressFunc : TSBMathProgressFunc  =  nil;
  Data :  pointer   =  nil;
  RaiseExceptionOnCancel : boolean  =  false): Boolean;
var
  I: Integer;
  Rs: Cardinal;
  RmCount: Integer;
  Res: boolean;
begin
  if P.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  RmCount := 8;
  Result := True;
  Res := false;
  Rs := 0;
  
  {$ifndef SB_PGPSFX_STUB}
  for I := 0 to 511 do
  begin
    LModSh(P, SmallPrimes[I], Rs);
    if (Rs = 0) then
    begin
      Result := False;
      Exit;
    end;
  end;
   {$endif SB_PGPSFX_STUB}

  for I := 1 to RmCount do
  begin
    try
      Res := LRabinMillerPrimeTest(P, ProgressFunc, Data, true)
    except
      Result := false;

      if RaiseExceptionOnCancel then
        raise EElMathException.Create(SMathOperationCanceled)
      else
        Exit;
    end;

    if not Res then
    begin
      Result := False;
      Exit;
    end;
  end;
end;

function LRabinMillerPrimeTest(P: PLInt;
  ProgressFunc : TSBMathProgressFunc  =  nil;
  Data :  pointer   =  nil;
  RaiseExceptionOnCancel : boolean  =  false): Boolean;
var
  Z, Pdec, M, A: PLInt;
  B, J: LongWord;
begin
  if P.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  LCreate(Pdec);
  LCreate(Z);
  LCreate(M);
  LCreate(A);
  LSub(P, Z, Pdec);
  B := 0;
  LCopy(M, Pdec);
  while (LEven(M)) do
  begin
    LShrNum(M, Z, 1);
    LSwap(Z, M);
    B := B + 1;
  end;

  if (P.Length > 1) then
  begin
    LGenerate(A, P.Length - 1);
//      LGenerate (a, 1);
  end
  else
  begin
    A.Digits[1] := P.Digits[1] - LongWord(SBRndGenerate(P.Digits[1] - 1)) - 1;
    if A.Digits[1] = 0 then A.Digits[1] := P.Digits[1] - 1;
  end;

  J := 0;

  try
    LMModPower(A, M, P, Z, ProgressFunc, Data, true);
  except
    Result := false;

    LDestroy(A);
    LDestroy(M);
    LDestroy(Z);
    LDestroy(PDec);

    if RaiseExceptionOnCancel then
      raise EElMathException.Create(SMathOperationCanceled)
    else
      Exit;    
  end;

  if ((Z.Length = 1) and (Z.Digits[1] = 1)) or (LEqual(Z, Pdec)) then
  begin
    Result := True;
    LDestroy(A);
    LDestroy(M);
    LDestroy(Z);
    LDestroy(PDec);
    Exit;
  end;

  while (J < B) do
  begin
    J := J + 1;
    if (J < B) and (not LEqual(Z, Pdec)) then
    begin
      LMult(Z, Z, M);
      LMod(M, P, Z);
    end
    else
      if (LEqual(Z, Pdec)) then
      begin
        Result := True;
        LDestroy(A);
        LDestroy(M);
        LDestroy(Z);
        LDestroy(PDec);
        Exit;
      end;
  end;
  Result := False;
  LDestroy(Pdec);
  LDestroy(Z);
  LDestroy(M);
  LDestroy(A);
end;

procedure LModSh(A: PLInt; B: LongWord; var Res: Cardinal);
var
  Count: integer;
  Value: TSBInt64;
begin
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);
  if B = 0 then
    raise EElMathException.Create(sDivisionByZero);

  Count := A.Length;
  Value := A.Digits[Count];
  Res := 0;
  while True do
  begin
    TSuperBaseRec(Value).Hi := Value mod B;
    Dec(Count);
    if Count <= 0 then
      Break;
    TSuperBaseRec(Value).Lo := A.Digits[Count];
  end;
  Res := TSuperBaseRec(Value).Hi;
end;

{$ifndef SB_PGPSFX_STUB}
procedure LGenPrime(P: PLInt; Len: Integer; RSAPrime: boolean{$ifdef HAS_DEF_PARAMS} =  false {$endif};
  ProgressFunc : TSBMathProgressFunc  =  nil; Data :  pointer   =  nil;
  RaiseExceptionOnCancel: boolean  =  false);
var
  Primes: Integer;
  Mods: array[1..300] of LongWord;
  I: Integer;
  A, B, C, One: PLInt;
  T: Cardinal;
begin
  if P.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  Primes := 300;
  LCreate(A);
  LCreate(B);
  LCreate(C);
  LCreate(One);
  SBRndGenerateLInt(P, Len * 4);

  P.Digits[1] := P.Digits[1] or 1;
  P.Digits[P.Length] := P.Digits[P.Length] or $80000000;

  { for RSA prime, also turning on the second major bit }
  if RSAPrime then
    P.Digits[P.Length] := P.Digits[P.Length] or $40000000;

  for I := 1 to 300 do
    LModSh(P, SmallPrimes[I], Mods[I]);
  while True do
  begin
    I := 1;
    while (Mods[I] <> 0) and (I < Primes) do
      Inc(I);

    if I >= Primes then
    begin
      I := 1;
      LSub(P, One, B);
      while True do
      begin
        A.Digits[1] := SmallPrimes[I];
        A.Length := 1;
        try
          LMModPower(A, B, P, C, ProgressFunc, Data, true);
        except
          if RaiseExceptionOnCancel then
            raise EElMathException.Create(SMathOperationCanceled)
          else
            Exit;
        end;
        LTrim(C);
        if not ((C.Digits[1] = 1) and (C.Length = 1)) then
          Break;
        Inc(I);
        if I > 5 then
        begin
          LDestroy(A);
          LDestroy(B);
          LDestroy(C);
          LDestroy(One);
          Exit;
        end;
      end;
    end;
    { trying next }
    LInc(P);
    LInc(P);

    for I := 1 to Primes do
    begin
      T := Mods[I] + 2;
      if T >= SmallPrimes[I] then
        Dec(T, SmallPrimes[I]);
      Mods[I] := T;
    end;
  end;
  LDestroy(A);
  LDestroy(B);
  LDestroy(C);
  LDestroy(One);
end;

procedure LGenPrimeEx(P: PLInt; Bits: Integer; RSAPrime: boolean{$ifdef HAS_DEF_PARAMS} =  false {$endif};
  ProgressFunc : TSBMathProgressFunc  =  nil; Data :  pointer   =  nil;
  RaiseExceptionOnCancel: boolean  =  false);
var
  Primes: Integer;
  Mods: array of LongWord;
  I, J: Integer;
  A, B, C: PLInt;
  T: Cardinal;
  Ctx: TRC4RandomContext;
  Mask : cardinal;
begin
  if P.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  Primes := SmallPrimesCount - 1;
  SetLength(Mods, Primes + 1);

  LCreate(A);
  LCreate(B);
  LCreate(C);
  LRC4Init(Ctx);

  Mask := $ffffffff;
  if (Bits mod 32) > 0 then
    for I := 31 downto (Bits mod 32) do
      Mask := Mask xor Cardinal(1 shl I);

  try
    repeat
      SBRndGenerateLInt(P, (Bits + 7) shr 3);

      P.Digits[P.Length] := P.Digits[P.Length] and Mask;

      P.Digits[1] := P.Digits[1] or 1;
      P.Digits[P.Length] := P.Digits[P.Length] or (1 shl ((31 + Bits mod 32) mod 32));

      { for RSA prime, also turning on the second major bit }
      if RSAPrime then
        if Bits mod 32 = 1 then
          P.Digits[P.Length - 1] := P.Digits[P.Length - 1] or $40000000
        else
          P.Digits[P.Length] := P.Digits[P.Length] or (1 shl ((30 + Bits mod 32) mod 32));

      for I := 1 to Primes do
        LModSh(P, SmallPrimes[I], Mods[I]);

      for J := 1 to 10000 do
      begin
        I := 1;

        while (Mods[I] <> 0) and (I < Primes) do Inc(I);

        if MathOperationCanceled(ProgressFunc, Data) then
          if RaiseExceptionOnCancel then
            raise EElMathException.Create(SMathOperationCanceled)
          else
            Exit;

        if I >= Primes then
        begin
          I := 1;

          try
            while (I <= 5) and LRabinMillerPrimeTest(P, ProgressFunc, Data, true) do Inc(I);
          except
            if RaiseExceptionOnCancel then
              raise EElMathException.Create(SMathOperationCanceled)
            else
              Exit;
          end;

          if I > 5 then Exit; //generation finished
        end;

        { trying next }

        LAdd(P, 2, P);

        for I := 1 to Primes do
        begin
          T := Mods[I] + 2;
          if T >= SmallPrimes[I] then
            Dec(T, SmallPrimes[I]);
          Mods[I] := T;
        end;
      end;

    until false;
  finally
    LDestroy(A);
    LDestroy(B);
    LDestroy(C);
  end;
end;
 {$endif SB_PGPSFX_STUB}

procedure LRC4Randomize(var Ctx: TRC4RandomContext; Key: PLInt);
var
  I: Integer;
  C: Byte;
  K: array[0..255] of Byte;
  L, J: Word;
  P: Byte;
begin
  if Key.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  for I := 0 to 255 do
    Ctx.S[I] := Byte(I);

  J := 0;
  L := 1;
  C := 0;
  while (J < 256) do
  begin
    K[J] := (Key.Digits[l] shr C) and 255;
    C := Byte(C + 1);
    if C > 3 then
    begin
      L := L + 1;
      C := 0;
    end;
    if (L > Key.Length) then
      L := 1;
    J := J + 1;
  end;

  Ctx.J := 0;
  for I := 0 to 255 do
  begin
    Ctx.J := (Ctx.J + Ctx.S[I] + K[I]) mod 256;
    P := Ctx.S[I];
    Ctx.S[I] := Ctx.S[Ctx.J];
    Ctx.S[Ctx.J] := P;
  end;

  Ctx.J := 0;
  Ctx.I := 0;
  Ctx.RandomInit := True;
end;

procedure LRC4Init(var Ctx: TRC4RandomContext);
var
  A: PLInt;
begin

  LCreate(A);
  LGenerate(A, RandKeyLength);
  LRC4Randomize(Ctx, A);
  LDestroy(A);
end;

function LRC4RandomByte(var Ctx: TRC4RandomContext): Byte;
var
  P: Byte;
  T: Word;
begin
  if not Ctx.RandomInit then
    LRC4Init(Ctx);

  Ctx.I := (Word(Ctx.I) + 1) mod 256;
  Ctx.J := (Word(Ctx.J) + Word(Ctx.S[Ctx.I])) mod 256;
  P := Ctx.S[Ctx.I];
  Ctx.S[Ctx.I] := Ctx.S[Ctx.J];
  Ctx.S[Ctx.J] := P;
  T := (Word(Ctx.S[Ctx.I]) + Word(Ctx.S[Ctx.J])) mod 256;
  Result := Ctx.S[T]
end;

procedure LRandom(var Ctx: TRC4RandomContext; A: PLInt; Bytes: Integer);
var
  I: Integer;
  Tm: TSBInt64;
begin
  A.Length := Bytes shr 2 + 1;
  if A.Length > MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  for I := 1 to A.Length - 1 do
  begin
    A.Digits[I] := 0;
    Tm := LRC4RandomByte(Ctx);
    A.Digits[I] := A.Digits[I] or Tm;
    Tm := LRC4RandomByte(Ctx);
    A.Digits[I] := A.Digits[I] or (Tm shl 8);
    Tm := LRC4RandomByte(Ctx);
    A.Digits[I] := A.Digits[I] or (Tm shl 16);
    Tm := LRC4RandomByte(Ctx);
    A.Digits[I] := A.Digits[I] or (Tm shl 24);
  end;
  A.Digits[A.Length] := 0;
  for I := 1 to (Bytes mod 4) do
  begin
    A.Digits[A.Length] := A.Digits[A.Length] or (TSBInt64(LRC4RandomByte(Ctx))
      shl ((I - 1) shl 3));
  end;
  if (Bytes mod 4) = 0 then A.Length := A.Length - 1;
end;

(* deprecated

procedure LMontgomeryProduct(A, B, N, Ninv : PLInt; BitsInR : integer; var Res : PLInt);
var
  T, M, Tmp, R : PLInt;
  I, Bits : integer;
begin
  LCreate(T);
  LCreate(M);
  LCreate(Tmp);
  LCreate(R);
  Bits := LBitCount2(N);
  LZero(Tmp);
  for I := 1 to Bits do
  begin
    if LGetBit(A, I) = 1 then
    begin
      LAdd(Tmp, B, R);
      LSwap(Tmp, R);
    end;
    if LGetBit(Tmp, 1) = 1 then
    begin
      LAdd(Tmp, N, R);
      LSwap(Tmp, R);
    end;
    LShr(Tmp);
  end;
  LDestroy(T);
  LDestroy(M);
  LDestroy(Tmp);
  LDestroy(R);
end; *)

(*
procedure LGCD2(A, B : PLInt; var D, X, Y : PLInt);
var
  X1, X2, Y1, Y2, NL, Q, R : PLInt;
begin
  if LNull(B) then
  begin
    LCopy(D, A);
    LInit(X, '01');
    LInit(Y, '00');
    Exit;
  end;
  LCreate(X1);
  LCreate(X2);
  LCreate(Y1);
  LCreate(Y2);
  LCreate(NL);
  LCreate(Q);
  LCreate(R);
  LZero(X1);
  LZero(Y2);
  LZero(NL);
  while LGreater(B, NL) and not LEqual(B, NL) do
  begin
//    LDiv(A, B, Q);
  end;
  LDestroy(X1);
  LDestroy(X2);
  LDestroy(Y1);
  LDestroy(Y2);
  LDestroy(NL);
  LDestroy(Q);
  LDestroy(R);
end;
*)

(*  deprecated
procedure LMModPower2(M, E, N : PLInt; var Res : PLInt);
var
  BitsInR, I : integer;
  R, RInv, Tmp, NInv, MInv, XInv : PLInt;
begin
  LCreate(R);
  LCreate(Tmp);
  LCreate(RInv);
  LCreate(NInv);
  LCreate(MInv);
  LCreate(XInv);
  BitsInR := LBitCount2(N);
  LShlNum(Tmp, R, BitsInR);
  LGCD(R, N, Tmp, RInv);
  LGCD(N, R, Tmp, NInv);
  LSub(R, NInv, Tmp);
  LSwap(Tmp, NInv);

  LMod(R, N, Xinv);

  LMult(M, R, Tmp);
  LMod(Tmp, N, MInv);

  for I := BitsInR downto 1 do
  begin
    LMontgomeryProduct(XInv, XInv, N, NInv, BitsInR, Tmp);
    LSwap(Tmp, XInv);
    if LGetBit(E, I) = 1 then
    begin
      LMontgomeryProduct(MInv, XInv, N, NInv, BitsInR, Tmp);
      LSwap(Tmp, XInv);
    end;
  end;
  Tmp.Digits[1] := 1;
  Tmp.Length := 1;
  LMontgomeryProduct(XInv, Tmp, N, NInv, BitsInR, Res);
  LDestroy(R);
  LDestroy(Tmp);
  LDestroy(RInv);
  LDestroy(NInv);
  LDestroy(MInv);
  LDestroy(XInv);
end; *)


(* deprecated

procedure LMModPower3(X, E, N: PLInt; var Res: PLInt; BitCnt : integer);
var
  Tm, Xinv, Yinv: PLInt;
  I, Rs, Bitsinr: Integer;
  Tmp1, Tmp2, Tmp3: PLInt;
  N0: Cardinal;
begin
  // II 06/05/2003
  // II 06/05/2003 end
  LCreate(Xinv);
  LCreate(Yinv);
  LCreate(Tm);
  LCreate(Tmp1);
  LCreate(Tmp2);
  LCreate(Tmp3);

  Rs := LBitCount(E);   // II 25/03/2003
  while E.Length < N.Length do
  begin
    E.Length := E.Length + 1;
    E.Digits[E.Length] := 0;
  end;
  E.Digits[E.Length + 1] := 0;
//  Rs := LBitCount(E); // II 25/03/2003

  Bitsinr := E.Length * 32;

  Tmp1.Digits[1] := N.Digits[1];
  LShiftLeft(Tmp2, 1);
  LGCD(Tmp1, Tmp2, Tm, Tmp3);
  N0 := 4294967295 - Tmp3.Digits[1] + 1;

  LShlNum(Yinv, Xinv, Bitsinr);
  LMod(Xinv, N, Yinv);
  LShlNum(X, Tm, Bitsinr);
  LMod(Tm, N, Xinv);

  for I := Rs downto 1 do
  begin
    LMMulN0(Yinv, Yinv, N, Tm, N0);
    LSwap(Tm, Yinv);
    if LGetBit(E, I) = 1 then
    begin
      LMMulN0(Yinv, Xinv, N, Tm, N0);
      LSwap(Tm, Yinv);
    end;
  end;

  Xinv.Digits[1] := 1;
  Xinv.Length := 1;
  LMMulN0(Yinv, Xinv, N, Res, N0);
  LTrim(E);
  LDestroy(Xinv);
  LDestroy(Yinv);
  LDestroy(Tm);
  LDestroy(Tmp1);
  LDestroy(Tmp2);
  LDestroy(Tmp3);
end; *)

function LBitSet(A : PLInt; n : integer) : boolean;
begin
  if (n < 0) then
    Result := false
  else
    Result := (A.Digits[N shr 5 + 1] and (cardinal(1) shl (N and $1F))) <> 0;
end;

procedure LSetBit(var A : PLInt; n : integer; Value : boolean);
begin
  if (A.Length > MAXDIGIT) or (n shr 5 >= MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);

  if Value then
    A.Digits[n shr 5 + 1] := A.Digits[n shr 5 + 1] or (1 shl (n and $1F))
  else
    A.Digits[n shr 5 + 1] := A.Digits[n shr 5 + 1] and not (1 shl (n and $1F));
  if (n shr 5 + 1) > A.Length then
    A.Length := n shr 5 + 1;
end;

procedure LBitTruncate(var A : PLInt; Bits : integer);
var
  i : integer;
begin
  if A.Length >= ((Bits + 31) shr 5) then
  begin
    for i := (Bits + 31) shr 5 + 1 to A.Length do
      A.Digits[i] := 0;
    A.Length := (Bits + 31) shr 5;
    for i := A.Length * 32 - 1 downto Bits do
      LSetBit(A, i, false);
  end;
end;

procedure LModEx(X, N : PLInt; var Res : PLInt);
var
  I : integer;
  Cnt : integer;
  Tmp : PLInt;
begin
  if (X.Length > MAXDIGIT) or (N.Length > MAXDIGIT) then
    raise EElMathException.Create(sNumberTooLarge);
  if LNull(N) then
    raise EElMathException.Create(sDivisionByZero);

  LCreate(Tmp);
  LZero(Res);
  Cnt := LBitCount(X);
  for I := Cnt downto 1 do
  begin
    LShl(Res);
    Res.Digits[1] := Res.Digits[1] or cardinal(LGetBit(X, I));
    if LGreater(Res, N) then
    begin
      LSub(Res, N, Tmp);
      LCopy(Res, Tmp);
    end
    else if LEqual(Res, N) then
      LZero(Res);
  end;
  LDestroy(Tmp);
end;

function MathOperationCanceled(ProgressFunc : TSBMathProgressFunc; Data :  pointer ): boolean;
begin
  if Assigned(ProgressFunc) then
    Result := not ProgressFunc(Data)
  else
    Result := false;
end;


end.
