// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbgostcommon.pas' rev: 21.00

#ifndef SbgostcommonHPP
#define SbgostcommonHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbgostcommon
{
//-- type declarations -------------------------------------------------------
typedef System::Word UInt16;

typedef unsigned UInt32;

typedef StaticArray<StaticArray<System::Byte, 16>, 8> TElGostSubstBlock;

typedef void __fastcall (__closure *TElBlockConvert_proc)(const Sbtypes::ByteArray InBuf, int In_StartIdx, Sbtypes::ByteArray &OutBuf, int Out_StartIdx, bool Flag);

typedef void __fastcall (__closure *TElBlockProcess_proc)(const Sbtypes::ByteArray InBuf, int StartIdx);

class DELPHICLASS TElGOSTBase;
class PASCALIMPLEMENTATION TElGOSTBase : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	StaticArray<unsigned, 8> fKey;
	StaticArray<unsigned, 256> K87;
	StaticArray<unsigned, 256> K65;
	StaticArray<unsigned, 256> K43;
	StaticArray<unsigned, 256> K21;
	Sbtypes::ByteArray fTail;
	int fTailLen;
	__classmethod void __fastcall SetLength_BA(Sbtypes::ByteArray &Arr, int Size);
	__classmethod void __fastcall Copy_BA(const Sbtypes::ByteArray Src, Sbtypes::ByteArray &Dst, int DstSize);
	__classmethod unsigned __fastcall Buf_to_UInt(const Sbtypes::ByteArray InBuf, int In_StartIdx);
	__classmethod void __fastcall UInt_To_Buf(unsigned V, Sbtypes::ByteArray &OutBuf, int Out_StartIdx);
	__classmethod void __fastcall FillArray(Sbtypes::ByteArray &Arr, System::Byte V)/* overload */;
	__classmethod void __fastcall ArrayCopy(const Sbtypes::ByteArray Src, int Src_Idx, Sbtypes::ByteArray &Dst, int Dst_Idx, int Count);
	unsigned __fastcall F(unsigned V);
	void __fastcall Process_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx, Sbtypes::ByteArray &OutBuf, int Out_StartIdx, bool IsEncrypt);
	void __fastcall int_Encrypt(const Sbtypes::ByteArray InBuf, int In_StartIdx, Sbtypes::ByteArray &OutBuf, int Out_StartIdx);
	void __fastcall int_Decrypt(const Sbtypes::ByteArray InBuf, int In_StartIdx, Sbtypes::ByteArray &OutBuf, int Out_StartIdx);
	void __fastcall int_SetKey(const Sbtypes::ByteArray V);
	void __fastcall SetKey(const Sbtypes::ByteArray V);
	Sbtypes::ByteArray __fastcall GetKey(void);
	bool __fastcall Check_Tail(const Sbtypes::ByteArray InBuf, int &In_StartIdx, int &In_Len);
	void __fastcall Convert_Data(const Sbtypes::ByteArray InBuf, int In_StartIdx, int In_Len, Sbtypes::ByteArray &OutBuf, /* out */ int &Out_Len, int Out_StartIdx, bool Flag, TElBlockConvert_proc Cnv_proc);
	void __fastcall Process_Data(const Sbtypes::ByteArray InBuf, int In_StartIdx, int In_Len, TElBlockProcess_proc Process_proc);
	__classmethod virtual unsigned __fastcall GetBlockSize();
	
public:
	__fastcall TElGOSTBase(void)/* overload */;
	__fastcall TElGOSTBase(StaticArray<System::Byte, 16> const *SubstBlock)/* overload */;
	void __fastcall Init(StaticArray<System::Byte, 16> const *SubstBlock);
	__fastcall virtual ~TElGOSTBase(void);
	virtual void __fastcall Reset(void);
	virtual void __fastcall Clone(TElGOSTBase* Source);
	void __fastcall EncryptBlock(unsigned &B0, unsigned &B1);
	void __fastcall DecryptBlock(unsigned &B0, unsigned &B1);
	__classmethod TElGostSubstBlock __fastcall MakeSubstBlock(const System::UnicodeString GostSubstBlockHex);
};


//-- var, const, procedure ---------------------------------------------------
static const ShortInt c_GOST_BlockSize = 0x8;
static const ShortInt c_GOST_KeySize = 0x20;
extern PACKAGE System::UnicodeString SB_GOST3411_94_SBox;
extern PACKAGE System::UnicodeString SB_GOST28147_89_TestParamSet;
extern PACKAGE System::UnicodeString SB_GOST28147_89_CryptoPro_A_ParamSet;
extern PACKAGE System::UnicodeString SB_GOST28147_89_CryptoPro_B_ParamSet;
extern PACKAGE System::UnicodeString SB_GOST28147_89_CryptoPro_C_ParamSet;
extern PACKAGE System::UnicodeString SB_GOST28147_89_CryptoPro_D_ParamSet;
extern PACKAGE System::UnicodeString SB_GOSTR3411_94_TestParamSet;
extern PACKAGE System::UnicodeString SB_GOSTR3411_94_CryptoProParamSet;
extern PACKAGE int SB_GOSTR3410_94_TestParamSet_T;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_TestParamSet_P;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_TestParamSet_Q;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_TestParamSet_A;
extern PACKAGE int SB_GOSTR3410_94_CryptoPro_A_ParamSet_T;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_A_ParamSet_P;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_A_ParamSet_Q;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_A_ParamSet_A;
extern PACKAGE int SB_GOSTR3410_94_CryptoPro_B_ParamSet_T;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_B_ParamSet_P;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_B_ParamSet_Q;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_B_ParamSet_A;
extern PACKAGE int SB_GOSTR3410_94_CryptoPro_C_ParamSet_T;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_C_ParamSet_P;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_C_ParamSet_Q;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_C_ParamSet_A;
extern PACKAGE int SB_GOSTR3410_94_CryptoPro_D_ParamSet_T;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_D_ParamSet_P;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_D_ParamSet_Q;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_D_ParamSet_A;
extern PACKAGE int SB_GOSTR3410_94_CryptoPro_XchA_ParamSet_T;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_XchA_ParamSet_P;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_XchA_ParamSet_Q;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_XchA_ParamSet_A;
extern PACKAGE int SB_GOSTR3410_94_CryptoPro_XchB_ParamSet_T;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_XchB_ParamSet_P;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_XchB_ParamSet_Q;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_XchB_ParamSet_A;
extern PACKAGE int SB_GOSTR3410_94_CryptoPro_XchC_ParamSet_T;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_XchC_ParamSet_P;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_XchC_ParamSet_Q;
extern PACKAGE System::UnicodeString SB_GOSTR3410_94_CryptoPro_XchC_ParamSet_A;
extern PACKAGE StaticArray<System::Byte, 32> SB_GOST_CRYPTOPRO_KEYMESH_C;

}	/* namespace Sbgostcommon */
using namespace Sbgostcommon;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbgostcommonHPP
