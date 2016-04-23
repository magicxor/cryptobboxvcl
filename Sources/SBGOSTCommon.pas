(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBGOSTCommon;

interface

uses
  SBTypes,
  SBUtils,
  SBConstants;

type
  UInt16 = WORD;    //  2 byte
  UInt32 = DWORD;   //  4 byte

const
  c_GOST_BlockSize = 8;
  c_GOST_KeySize = 32;

type
  TElGostSubstBlock = array[1..8, 0..15] of byte;

  TElBlockConvert_proc = 
      procedure(const InBuf: ByteArray; In_StartIdx: integer;
                var OutBuf: ByteArray; Out_StartIdx: integer;
                Flag: Boolean) of object;

  TElBlockProcess_proc = 
      procedure(const InBuf: ByteArray; StartIdx: integer) of object;

  TElGOSTBase = class
  protected
    fKey:  array[0..7] of UInt32 ;
    K87:  array[0..255] of UInt32 ;
    K65:  array[0..255] of UInt32 ;
    K43:  array[0..255] of UInt32 ;
    K21:  array[0..255] of UInt32 ;
    fTail: ByteArray;
    fTailLen: integer;
    class procedure SetLength_BA(var Arr: ByteArray; Size: integer); 
    class procedure Copy_BA(const Src: ByteArray; var Dst: ByteArray; DstSize: integer); 
    class function  Buf_to_UInt(const InBuf: ByteArray; In_StartIdx: integer): UInt32; 
    class procedure UInt_To_Buf(V: UInt32; var OutBuf: ByteArray; Out_StartIdx: integer); 
//    class procedure FillArray(var Arr: ByteArray; Size: integer; V: byte); {$ifndef SB_NET}overload;{$endif}
    class procedure FillArray(var Arr: ByteArray; V: byte);  overload;   
    class procedure ArrayCopy(const Src: ByteArray; Src_Idx: integer; 
                              var Dst: ByteArray; Dst_Idx, Count: integer); 
    function  F(V: UInt32): UInt32;
    procedure Process_Block(const InBuf: ByteArray; In_StartIdx: integer;
                          var OutBuf: ByteArray; Out_StartIdx: integer;
                          IsEncrypt: Boolean); 
    procedure int_Encrypt(const InBuf: ByteArray; In_StartIdx: integer;
                          var OutBuf: ByteArray; Out_StartIdx: integer);
    procedure int_Decrypt(const InBuf: ByteArray; In_StartIdx: integer;
                          var OutBuf: ByteArray; Out_StartIdx: integer);
    procedure int_SetKey(const V: ByteArray);
    procedure SetKey(const V: ByteArray); 
    function  GetKey: ByteArray; 
    function  Check_Tail(const InBuf: ByteArray; var In_StartIdx: integer;
                         var In_Len: integer): Boolean;
    procedure Convert_Data(const InBuf: ByteArray; In_StartIdx: integer;
                In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
                Out_StartIdx: integer; Flag: Boolean;
                Cnv_proc: TElBlockConvert_proc);
    procedure Process_Data(const InBuf: ByteArray; In_StartIdx: integer;
                In_Len: integer; Process_proc: TElBlockProcess_proc);
    class function  GetBlockSize(): cardinal; virtual;  
  public
    constructor Create();  overload; 
    constructor Create(const SubstBlock: TElGostSubstBlock);  overload; 
    procedure Init(const SubstBlock: TElGostSubstBlock);
     destructor  Destroy; override;
    procedure Reset; virtual;
    procedure Clone(Source: TElGOSTBase); virtual;
    procedure EncryptBlock(var B0, B1 : cardinal);
    procedure DecryptBlock(var B0, B1 : cardinal);
    class function MakeSubstBlock(const GostSubstBlockHex: string): TElGostSubstBlock; 
  end;


const
  // from GOST 34.11-1994
  SB_GOST3411_94_SBox: string =
    '4E5764D1AB8DCBBF941A7A4D2CD11010' +
    'D6A057358D38F2F70F49D15AEA2F8D94' +
    '62EE4309B3F4A6A218C698E3C17CE57E' +
    '706B0966F7023C8B5595BF2839B32ECC';

  //  from RFC 4357
  SB_GOST28147_89_TestParamSet: string =
    '4CDE389C2989EFB6FFEB56C55EC29B02' +
    '9875613B113F896003970C798AA1D55D' +
    'E210AD43375DB38EB42C77E7CD46CAFA' +
    'D66A201F70F41EA4AB03F22165B844D8';

  SB_GOST28147_89_CryptoPro_A_ParamSet: string =
    '93EEB31B67475ADA3E6A1D2F292C9C95' +
    '88BD8170BA31D2AC1FD3F06E70890B08' +
    'A5C0E78642F245C2E65B2943FCA43459' +
    'CB0FC8F104787F37DD15AEBD519666E4';

  SB_GOST28147_89_CryptoPro_B_ParamSet: string =
    '80E7285041C57324B200C2AB1AADF6BE' +
    '349B94985D265D1305D1AEC79CB2BB31' +
    '29731C7AE75A4142A38C07D9CFFFDF06' +
    'DB346A6F686E80FD7619E985FE4835EC';

  SB_GOST28147_89_CryptoPro_C_ParamSet: string =
    '10838CA7B126D994C750BB602D010185' +
    '9B4548DAD49D5EE205FA122FF2A8240E' +
    '483B97FC5E7233368FC9C651ECD7E5BB' +
    'A96E6A4D7AEFF019661CAFC333B47D78';

  SB_GOST28147_89_CryptoPro_D_ParamSet: string =
    'FB110831C6C5C00A23BE8F66A40C93F8' +
    '6CFAD21F4FE725EB5E60AE90025DBB24' +
    '77A671DC9DD23A83E84B64C5D0845749' +
    '15994CB7BA33E9AD897FFD523128167E';

  SB_GOSTR3411_94_TestParamSet: string =
    '4E5764D1AB8DCBBF941A7A4D2CD11010' +
    'D6A057358D38F2F70F49D15AEA2F8D94' +
    '62EE4309B3F4A6A218C698E3C17CE57E' +
    '706B0966F7023C8B5595BF2839B32ECC';

  SB_GOSTR3411_94_CryptoProParamSet: string =
    'A57477D14FFA66E354C7424A60ECB419' +
    '82909D751D4FC90B3B122F547908A0AF' +
    'D13E1A38C7B181C6E65605870325EBFE' +
    '9C6DF86D2EABDE20BA893C92F8D353BC';

  { GOST R3410-1994 RFC 4357 paramsets. T, P, Q, A. }

  SB_GOSTR3410_94_TestParamSet_T: integer = 512;
  SB_GOSTR3410_94_TestParamSet_P: string =
    'EE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386' +
    'EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3';
  SB_GOSTR3410_94_TestParamSet_Q: string =
    '98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D';
  SB_GOSTR3410_94_TestParamSet_A: string =
    '9E96031500C8774A869582D4AFDE2127AFAD2538B4B6270A6F7C8837B50D50F2' +
    '06755984A49E509304D648BE2AB5AAB18EBE2CD46AC3D8495B142AA6CE23E21C';

  SB_GOSTR3410_94_CryptoPro_A_ParamSet_T: integer = 1024;
  SB_GOSTR3410_94_CryptoPro_A_ParamSet_P: string =
    'B4E25EFB018E3C8B87505E2A67553C5EDC56C2914B7E4F89D23F03F03377E70A' +
    '2903489DD60E78418D3D851EDB5317C4871E40B04228C3B7902963C4B7D85D52' +
    'B9AA88F2AFDBEB28DA8869D6DF846A1D98924E925561BD69300B9DDD05D247B5' +
    '922D967CBB02671881C57D10E5EF72D3E6DAD4223DC82AA1F7D0294651A480DF';
  SB_GOSTR3410_94_CryptoPro_A_ParamSet_Q: string =
    '972432A437178B30BD96195B773789AB2FFF15594B176DD175B63256EE5AF2CF';
  SB_GOSTR3410_94_CryptoPro_A_ParamSet_A: string =
    '8FD36731237654BBE41F5F1F8453E71CA414FFC22C25D915309E5D2E62A2A26C' +
    '7111F3FC79568DAFA028042FE1A52A0489805C0DE9A1A469C844C7CABBEE625C' +
    '3078888C1D85EEA883F1AD5BC4E6776E8E1A0750912DF64F79956499F1E18247' +
    '5B0B60E2632ADCD8CF94E9C54FD1F3B109D81F00BF2AB8CB862ADF7D40B9369A';

  SB_GOSTR3410_94_CryptoPro_B_ParamSet_T: integer = 1024;
  SB_GOSTR3410_94_CryptoPro_B_ParamSet_P: string =
    'C6971FC57524B30C9018C5E621DE15499736854F56A6F8AEE65A7A404632B1BC' +
    'F0349FFCAFCB0A103177971FC1612ADCDB8C8CC938C70225C8FD12AFF01B1D06' +
    '4E0AD6FDE6AB9159166CB9F2FC171D92F0CC7B6A6B2CD7FA342ACBE2C9315A42' +
    'D576B1ECCE77A963157F3D0BD96A8EB0B0F3502AD238101B05116334F1E5B7AB';
  SB_GOSTR3410_94_CryptoPro_B_ParamSet_Q: string =
    'B09D634C10899CD7D4C3A7657403E05810B07C61A688BAB2C37F475E308B0607';
  SB_GOSTR3410_94_CryptoPro_B_ParamSet_A: string =
    '3D26B467D94A3FFC9D71BF8DB8934084137264F3C2E9EB16DCA214B8BC7C8724' +
    '85336744934FD2EF5943F9ED0B745B90AA3EC8D70CDC91682478B664A2E1F8FB' +
    '56CEF2972FEE7EDB084AF746419B854FAD02CC3E3646FF2E1A18DD4BEB3C44F7' +
    'F2745588029649674546CC9187C207FB8F2CECE8E2293F68395C4704AF04BAB5';

  SB_GOSTR3410_94_CryptoPro_C_ParamSet_T: integer = 1024;
  SB_GOSTR3410_94_CryptoPro_C_ParamSet_P: string =
    '9D88E6D7FE3313BD2E745C7CDD2AB9EE4AF3C8899E847DE74A33783EA68BC305' +
    '88BA1F738C6AAF8AB350531F1854C3837CC3C860FFD7E2E106C3F63B3D8A4C03' +
    '4CE73942A6C3D585B599CF695ED7A3C4A93B2B947B7157BB1A1C043AB41EC856' +
    '6C6145E938A611906DE0D32E562494569D7E999A0DDA5C879BDD91FE124DF1E9';
  SB_GOSTR3410_94_CryptoPro_C_ParamSet_Q: string =
    'FADD197ABD19A1B4653EECF7ECA4D6A22B1F7F893B641F901641FBB555354FAF';
  SB_GOSTR3410_94_CryptoPro_C_ParamSet_A: string =
    '7447ED7156310599070B12609947A5C8C8A8625CF1CF252B407B331F93D639DD' +
    'D1BA392656DECA992DD035354329A1E95A6E32D6F47882D960B8F10ACAFF796D' +
    '13CD9611F853DAB6D2623483E46788708493937A1A29442598AEC2E074202256' +
    '3440FE9C18740ECE6765AC05FAF024A64B026E7E408840819E962E7E5F401AE3';

  SB_GOSTR3410_94_CryptoPro_D_ParamSet_T: integer = 1024;
  SB_GOSTR3410_94_CryptoPro_D_ParamSet_P: string =
    '80F102D32B0FD167D069C27A307ADAD2C466091904DBAA55D5B8CC7026F2F7A1' +
    '919B890CB652C40E054E1E9306735B43D7B279EDDF9102001CD9E1A831FE8A16' +
    '3EED89AB07CF2ABE8242AC9DEDDDBF98D62CDDD1EA4F5F15D3A42A6677BDD293' +
    'B24260C0F27C0F1D15948614D567B66FA902BAA11A69AE3BCEADBB83E399C9B5';
  SB_GOSTR3410_94_CryptoPro_D_ParamSet_Q: string =
    'F0F544C418AAC234F683F033511B65C21651A6078BDA2D69BB9F732867502149';
  SB_GOSTR3410_94_CryptoPro_D_ParamSet_A: string =
    '6BCC0B4FADB3889C1E06ADD23CC09B8AB6ECDEDF73F04632595EE4250005D6AF' +
    '5F5ADE44CB1E26E6263C672347CFA26F9E9393681E6B759733784CDE5DBD9A14' +
    'A39369DFD99FA85CC0D10241C4010343F34A91393A706CF12677CBFA1F578D6B' +
    '6CFBE8A1242CFCC94B3B653A476E145E3862C18CC3FED8257CFEF74CDB205BF1';

  SB_GOSTR3410_94_CryptoPro_XchA_ParamSet_T: integer = 1024;
  SB_GOSTR3410_94_CryptoPro_XchA_ParamSet_P: string =
    'CA3B3F2EEE9FD46317D49595A9E7518E6C63D8F4EB4D22D10D28AF0B8839F079' +
    'F8289E603B03530784B9BB5A1E76859E4850C670C7B71C0DF84CA3E0D6C177FE' +
    '9F78A9D8433230A883CD82A2B2B5C7A3306980278570CDB79BF01074A69C9623' +
    '348824B0C53791D53C6A78CAB69E1CFB28368611A397F50F541E16DB348DBE5F';
  SB_GOSTR3410_94_CryptoPro_XchA_ParamSet_Q: string =
    'CAE4D85F80C147704B0CA48E85FB00A9057AA4ACC44668E17F1996D7152690D9';
  SB_GOSTR3410_94_CryptoPro_XchA_ParamSet_A: string =
    'BE27D652F2F1E339DA734211B85B06AE4DE236AA8FBEEB3F1ADCC52CD4385377' +
    '7E834A6A518138678A8ADBD3A55C70A7EAB1BA7A0719548677AAF4E609FFB47F' +
    '6B9D7E45B0D06D83D7ADC53310ABD85783E7317F7EC73268B6A9C08D260B85D8' +
    '485696CA39C17B17F044D1E050489036ABD381C5E6BF82BA352A1AFF136601AF';

  SB_GOSTR3410_94_CryptoPro_XchB_ParamSet_T: integer = 1024;
  SB_GOSTR3410_94_CryptoPro_XchB_ParamSet_P: string =
    '9286DBDA91ECCFC3060AA5598318E2A639F5BA90A4CA656157B2673FB191CD05' +
    '89EE05F4CEF1BD13508408271458C30851CE7A4EF534742BFB11F4743C8F787B' +
    '11193BA304C0E6BCA25701BF88AF1CB9B8FD4711D89F88E32B37D95316541BF1' +
    'E5DBB4989B3DF13659B88C0F97A3C1087B9F2D5317D557DCD4AFC6D0A754E279';
  SB_GOSTR3410_94_CryptoPro_XchB_ParamSet_Q: string =
    'C966E9B3B8B7CDD82FF0F83AF87036C38F42238EC50A876CD390E43D67B6013F';
  SB_GOSTR3410_94_CryptoPro_XchB_ParamSet_A: string =
    '7E9C3096676F51E3B2F9884CF0AC2156779496F410E049CED7E53D8B7B5B366B' +
    '1A6008E5196605A55E89C3190DABF80B9F1163C979FCD18328DAE5E9048811B3' +
    '70107BB7715F82091BB9DE0E33EE2FED6255474F8769FCE5EAFAEEF1CB5A32E0' +
    'D5C6C2F0FC0B3447072947F5B4C387666993A333FC06568E534AD56D2338D729';

  SB_GOSTR3410_94_CryptoPro_XchC_ParamSet_T: integer = 1024;
  SB_GOSTR3410_94_CryptoPro_XchC_ParamSet_P: string =
    'B194036ACE14139D36D64295AE6C50FC4B7D65D8B340711366CA93F383653908' +
    'EE637BE428051D86612670AD7B402C09B820FA77D9DA29C8111A8496DA6C261A' +
    '53ED252E4D8A69A20376E6ADDB3BDCD331749A491A184B8FDA6D84C31CF05F91' +
    '19B5ED35246EA4562D85928BA1136A8D0E5A7E5C764BA8902029A1336C631A1D';
  SB_GOSTR3410_94_CryptoPro_XchC_ParamSet_Q: string =
    '96120477DF0F3896628E6F4A88D83C93204C210FF262BCCB7DAE450355125259';
  SB_GOSTR3410_94_CryptoPro_XchC_ParamSet_A: string =
    '3F1817052BAA7598FE3E4F4FC5C5F616E122CFF9EBD89EF81DC7CE8BF56CC64B' +
    '43586C80F1C4F56DD5718FDD76300BE336784259CA25AADE5A483F64C02A20CF' +
    '4A10F9C189C433DEFE31D263E6C9764660A731ECCAECB74C8279303731E8CF69' +
    '205BC73E5A70BDF93E5BB681DAB4EEB9C733CAAB2F673C475E0ECA921D29782E';


  SB_GOST_CRYPTOPRO_KEYMESH_C: array [0..31] of byte =
   ( 
    $69, $00, $72, $22, $64, $C9, $04, $23, $8D, $3A, $DB, $96, $46, $E9, $2A, $C4,
    $18, $FE, $AC, $94, $00, $ED, $07, $12, $C0, $86, $DC, $C2, $EF, $4C, $A9, $2B
   ) ;

implementation

class function  TElGOSTBase.MakeSubstBlock(const GostSubstBlockHex: string): TElGostSubstBlock;
var
  T: ByteArray;
  L, i, Pi, R: integer;
begin
  if  Length(GostSubstBlockHex) <> 128  then
    raise ESecureBlackboxError.Create('Invalid size. 128 is expected ');

  L := 64;
  SetLength_BA(T, L);
  SBUtils.StringToBinary(GostSubstBlockHex, @T[0], L);

  Pi := 1;    R := 0;

  for i := 0 to 63 do
  begin
    Result[Pi, R] := (T[i] shr 4) and $0F;
    Result[Pi + 1, R] := T[i] and $0F;
    inc(Pi, 2);

    if  Pi > 8  then
    begin
      Pi := 1;
      inc(R);
    end;
  end;

end;

class procedure TElGOSTBase.SetLength_BA(var Arr: ByteArray; Size: integer);
begin
  if  Length(Arr) <> Size  then
    SetLength(Arr, Size);
end;

class procedure TElGOSTBase.Copy_BA(const Src: ByteArray; var Dst: ByteArray; DstSize: integer);
var
  i, N: integer;
begin
  SetLength_BA(Dst, DstSize);
  N := Length(Src);

  if  N > DstSize then
    N := DstSize;

  for i := 0 to N - 1 do
    Dst[i] := Src[i];

  if  N < DstSize then
    for i := N to DstSize - 1 do
      Dst[i] := 0;
end;

class function  TElGOSTBase.Buf_to_UInt(const InBuf: ByteArray; In_StartIdx: integer): UInt32;
begin
  Result := InBuf[In_StartIdx + 0] or (InBuf[In_StartIdx + 1] shl 8) or
       (InBuf[In_StartIdx + 2] shl 16) or (InBuf[In_StartIdx + 3] shl 24);
end;

class procedure TElGOSTBase.UInt_To_Buf(V: UInt32; var OutBuf: ByteArray; Out_StartIdx: integer);
begin
  OutBuf[Out_StartIdx + 0] := V and $FF;
  OutBuf[Out_StartIdx + 1] := (V shr 8) and $FF;
  OutBuf[Out_StartIdx + 2] := (V shr 16)and $FF;
  OutBuf[Out_StartIdx + 3] := (V shr 24)and $FF;
end;

class procedure TElGOSTBase.FillArray(var Arr: ByteArray; V: byte);
var
  i: integer;
begin
  for i := Low(Arr) to High(Arr) do
    Arr[i] := V;
end;

class procedure TElGOSTBase.ArrayCopy(const Src: ByteArray; Src_Idx: integer;
                              var Dst: ByteArray; Dst_Idx, Count: integer);
var
  i, N: integer;
begin
  N := Count - 1;

  for i := 0 to N do
    Dst[Dst_Idx + i] := Src[Src_Idx + i];
end;

constructor TElGOSTBase.Create(const SubstBlock: TElGostSubstBlock);
begin
  inherited Create();
  Init(SubstBlock);
end;

constructor TElGOSTBase.Create();
begin
  inherited Create();
  K87[0] := 0;
  K87[1] := 0;
end;

procedure TElGOSTBase.Init(const SubstBlock: TElGostSubstBlock);
var
  i: integer;
  X: UINT32;
  HB, LB: integer;

  function  CalcPair(B1, B2: byte; Shift: integer): UINT32;
  begin
    X := ((B1 shl 4) or B2) shl Shift;
    Result := (X shl 11) or (X shr 21);
  end;

begin
  for i := 0 to 255 do
  begin
    HB := i shr 4;
    LB := i and $0F;
    K87[i] := CalcPair(SubstBlock[8, HB], SubstBlock[7, LB], 24);
    K65[i] := CalcPair(SubstBlock[6, HB], SubstBlock[5, LB], 16);
    K43[i] := CalcPair(SubstBlock[4, HB], SubstBlock[3, LB], 8);
    K21[i] := CalcPair(SubstBlock[2, HB], SubstBlock[1, LB], 0);
  end;

  Reset();
end;

class function  TElGOSTBase.GetBlockSize(): cardinal;
begin
  Result := 0;
end;

 destructor  TElGOSTBase.Destroy;
begin
  inherited;
end;

function  TElGOSTBase.F(V: UInt32): UInt32;
begin
  Result := K87[(V shr 24) and $FF] or K65[(V shr 16) and $FF] or
            K43[(V shr 8) and $FF] or K21[V and $FF];
end;          

procedure TElGOSTBase.EncryptBlock(var B0, B1 : cardinal);
var
  F, N1, N2 : cardinal;
begin
  N1 := B0;
  N2 := B1;

  F := N1 + fKey[0];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[1];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[2];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[3];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[4];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[5];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[6];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[7];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);

  F := N1 + fKey[0];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[1];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[2];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[3];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[4];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[5];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[6];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[7];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);

  F := N1 + fKey[0];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[1];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[2];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[3];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[4];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[5];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[6];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[7];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);

  F := N1 + fKey[7];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[6];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[5];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[4];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[3];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[2];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[1];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[0];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);

  B0 := N2;
  B1 := N1;
end;

procedure TElGOSTBase.DecryptBlock(var B0, B1 : cardinal);
var
  F, N1, N2 : cardinal;
begin
  N1 := B0;
  N2 := B1;

  F := N1 + fKey[0];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[1];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[2];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[3];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[4];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[5];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[6];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[7];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);

  F := N1 + fKey[7];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[6];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[5];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[4];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[3];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[2];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[1];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[0];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);

  F := N1 + fKey[7];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[6];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[5];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[4];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[3];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[2];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[1];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[0];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);

  F := N1 + fKey[7];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[6];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[5];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[4];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[3];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[2];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N1 + fKey[1];
  N2 := N2 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);
  F := N2 + fKey[0];
  N1 := N1 xor (K87[(F shr 24) and $FF] or K65[(F shr 16) and $FF] or K43[(F shr 8) and $FF] or K21[F and $FF]);

  B0 := N2;
  B1 := N1;
end;

procedure TElGOSTBase.Process_Block(const InBuf: ByteArray; In_StartIdx: integer;
                          var OutBuf: ByteArray; Out_StartIdx: integer;
                          IsEncrypt: Boolean);
var
  N1, N2: UInt32;

  procedure Set_N1(Idx: integer);
  begin
    N1 := N1 xor F(N2 + fKey[Idx]);
  end;

  procedure Set_N2(Idx: integer);
  begin
    N2 := N2 xor F(N1 + fKey[Idx]);
  end;

  procedure R_0_7();
  begin
    Set_N2(0);    Set_N1(1);
    Set_N2(2);    Set_N1(3);
    Set_N2(4);    Set_N1(5);
    Set_N2(6);    Set_N1(7);
  end;

  procedure R_7_0();
  begin
    Set_N2(7);    Set_N1(6);
    Set_N2(5);    Set_N1(4);
    Set_N2(3);    Set_N1(2);
    Set_N2(1);    Set_N1(0);
  end;

begin
  N1 := Buf_to_UInt(InBuf, In_StartIdx);
  N2 := Buf_to_UInt(InBuf, In_StartIdx + 4);

  if  IsEncrypt then
  begin
    R_0_7();
    R_0_7();
    R_0_7();
    R_7_0();
  end
  else
  begin
    R_0_7();
    R_7_0();
    R_7_0();
    R_7_0();
  end;

  UInt_To_Buf(N2, OutBuf, Out_StartIdx);
  UInt_To_Buf(N1, OutBuf, Out_StartIdx + 4);
end;

procedure TElGOSTBase.int_Encrypt(const InBuf: ByteArray; In_StartIdx: integer;
  var OutBuf: ByteArray; Out_StartIdx: integer);
var
  B0, B1 : cardinal;
begin
  B0 := Buf_to_UInt(InBuf, In_StartIdx);
  B1 := Buf_to_UInt(InBuf, In_StartIdx + 4);
  EncryptBlock(B0, B1);
  UInt_To_Buf(B0, OutBuf, Out_StartIdx);
  UInt_To_Buf(B1, OutBuf, Out_StartIdx + 4);
  //Process_Block(InBuf, In_StartIdx, OutBuf, Out_StartIdx, True);
end;

procedure TElGOSTBase.int_Decrypt(const InBuf: ByteArray; In_StartIdx: integer;
  var OutBuf: ByteArray; Out_StartIdx: integer);
var
  B0, B1 : cardinal;
begin
  B0 := Buf_to_UInt(InBuf, In_StartIdx);
  B1 := Buf_to_UInt(InBuf, In_StartIdx + 4);
  DecryptBlock(B0, B1);
  UInt_To_Buf(B0, OutBuf, Out_StartIdx);
  UInt_To_Buf(B1, OutBuf, Out_StartIdx + 4);  
  //Process_Block(InBuf, In_StartIdx, OutBuf, Out_StartIdx, False);
end;

procedure TElGOSTBase.int_SetKey(const V: ByteArray);
var
  i, N: integer;
begin
  N := 0;

  for i := Low(fKey) to High(fKey) do
  begin
    fKey[i] := Buf_to_UInt(V, N);
    inc(N, 4);
  end;
end;

procedure TElGOSTBase.SetKey(const V: ByteArray);
var
  tK: ByteArray;
begin
  Copy_BA(V, tK, c_GOST_KeySize);
  int_SetKey(tK);
end;

function  TElGOSTBase.GetKey: ByteArray;
var
  i, N: integer;
begin
  SetLength_BA(Result, c_GOST_KeySize);
  N := 0;

  for i := Low(fKey) to High(fKey) do
  begin
    UInt_To_Buf(fKey[i], Result, N);
    inc(N, 4);
  end;
end;

procedure TElGOSTBase.Reset;
begin
  fTailLen := 0;
  SetLength_BA(fTail, GetBlockSize());

  //  Check on uninitialized value
  if  K87[0] = K87[1] then
    Init(MakeSubstBlock(SB_GOST28147_89_CryptoPro_A_ParamSet));
end;

procedure TElGOSTBase.Clone(Source: TElGOSTBase);
var
  i: integer;
begin
  for i := Low(fKey) to High(fKey) do
    fKey[i] := Source.fKey[i];

  for i := Low(K87) to High(K87) do
  begin
    K87[i] := Source.K87[i];
    K65[i] := Source.K65[i];
    K43[i] := Source.K43[i];
    K21[i] := Source.K21[i];
  end;

  fTail := CloneArray(Source.fTail);
  fTailLen := Source.fTailLen;
end;

function  TElGOSTBase.Check_Tail(const InBuf: ByteArray;
                var In_StartIdx: integer; var In_Len: integer): Boolean;
var
  i, N, BlockSize: integer;
begin
  if  In_Len > 0 then
  begin
    BlockSize := GetBlockSize();

    if  fTailLen > 0  then
    begin
      if  (fTailLen + In_Len) >= BlockSize  then
        N := BlockSize - fTailLen
      else
        N := In_Len;
    end
    else
    if  In_Len < BlockSize  then
      N := In_Len
    else
      N := 0;

    if  N > 0 then
    begin
      for i := 0 to N - 1 do
        fTail[fTailLen + i] := InBuf[In_StartIdx + i];

      inc(fTailLen, N);
      inc(In_StartIdx, N);
      dec(In_Len, N)
    end;

    Result := (fTailLen = BlockSize) or (In_Len >= BlockSize);
  end
  else
    Result := False;
end;

procedure TElGOSTBase.Convert_Data(const InBuf: ByteArray; In_StartIdx: integer;
                In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
                Out_StartIdx: integer; Flag: Boolean;
                Cnv_proc: TElBlockConvert_proc);
var
  i, BlockSize: integer;
begin
  if  not Assigned(Cnv_proc)
      or not Check_Tail(InBuf, In_StartIdx, In_Len) then
    exit;

  BlockSize := GetBlockSize();
  Out_Len := ((fTailLen + In_Len) div BlockSize) * BlockSize;
  SetLength_BA(OutBuf, Out_StartIdx + Out_Len);

  if  fTailLen > 0  then
  begin
    Cnv_proc(fTail, 0, OutBuf, Out_StartIdx, Flag);
    inc(Out_StartIdx, BlockSize);
    fTailLen := 0;
  end;

  i := 0;

  while i < Out_Len do
  begin
    Cnv_proc(InBuf, In_StartIdx, OutBuf, Out_StartIdx + i, Flag);
    inc(i, BlockSize);
    inc(In_StartIdx, BlockSize);
    dec(In_Len, BlockSize);
  end;

  if  In_Len > 0 then
  begin
    fTailLen := In_Len;

    for i := 0 to In_Len - 1 do
      fTail[i] := InBuf[In_StartIdx + i];
  end;
end;

procedure TElGOSTBase.Process_Data(const InBuf: ByteArray; In_StartIdx: integer;
                In_Len: integer; Process_proc: TElBlockProcess_proc);
var
  i, BlockSize, QntSteps: integer;
begin
  if  not Assigned(Process_proc)
      or not Check_Tail(InBuf, In_StartIdx, In_Len) then
    exit;

  BlockSize := GetBlockSize();

  if  fTailLen > 0  then
  begin
    Process_proc(fTail, 0);
    fTailLen := 0;
  end;

  QntSteps := In_Len div BlockSize - 1;

  for i := 0 to QntSteps do
  begin
    Process_proc(InBuf, In_StartIdx);
    inc(In_StartIdx, BlockSize);
    dec(In_Len, BlockSize);
  end;

  if  In_Len > 0 then
  begin
    fTailLen := In_Len;

    for i := 0 to In_Len - 1 do
      fTail[i] := InBuf[In_StartIdx + i];
  end;
end;

end.


