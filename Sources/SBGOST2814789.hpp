// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbgost2814789.pas' rev: 21.00

#ifndef Sbgost2814789HPP
#define Sbgost2814789HPP

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
#include <Sbstreams.hpp>	// Pascal unit
#include <Sbgostcommon.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbgost2814789
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TElGOSTMode { GOSTMode_ECB, GOSTMode_OFB, GOSTMode_CFB, GOSTMode_CBC };
#pragma option pop

class DELPHICLASS TElGOST;
class PASCALIMPLEMENTATION TElGOST : public Sbgostcommon::TElGOSTBase
{
	typedef Sbgostcommon::TElGOSTBase inherited;
	
protected:
	TElGOSTMode fMode;
	Sbtypes::ByteArray fIV;
	Sbtypes::ByteArray fWork_IV;
	Sbtypes::ByteArray fGamma;
	Sbtypes::ByteArray fMAC;
	unsigned fN3;
	unsigned fN4;
	void __fastcall SetIV(const Sbtypes::ByteArray V);
	Sbtypes::ByteArray __fastcall GetIV(void);
	void __fastcall ECB_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx, Sbtypes::ByteArray &OutBuf, int Out_StartIdx, bool IsEncrypt);
	void __fastcall CFB_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx, Sbtypes::ByteArray &OutBuf, int Out_StartIdx, bool IsEncrypt);
	void __fastcall OFB_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx, Sbtypes::ByteArray &OutBuf, int Out_StartIdx, bool IsEncrypt);
	void __fastcall CBC_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx, Sbtypes::ByteArray &OutBuf, int Out_StartIdx, bool IsEncrypt);
	Sbgostcommon::TElBlockConvert_proc __fastcall Get_Block_Convertor(TElGOSTMode Mode);
	void __fastcall MAC_Block_proc(const Sbtypes::ByteArray InBuf, int In_StartIdx);
	void __fastcall ConvertStream(Classes::TStream* Source, unsigned Count, Classes::TStream* Dest, bool IsEncrypt);
	__classmethod virtual unsigned __fastcall GetBlockSize();
	
public:
	__classmethod int __fastcall BlockSize();
	__classmethod int __fastcall KeySize();
	__fastcall TElGOST(void)/* overload */;
	__fastcall TElGOST(StaticArray<System::Byte, 16> const *SubstBlock)/* overload */;
	__fastcall virtual ~TElGOST(void);
	virtual void __fastcall Reset(void);
	virtual void __fastcall Clone(Sbgostcommon::TElGOSTBase* Source);
	void __fastcall Encrypt_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx, int In_Len, Sbtypes::ByteArray &OutBuf, /* out */ int &Out_Len, int Out_StartIdx);
	void __fastcall Decrypt_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx, int In_Len, Sbtypes::ByteArray &OutBuf, /* out */ int &Out_Len, int Out_StartIdx);
	void __fastcall Encrypt_Finalize(Sbtypes::ByteArray &OutBuf, /* out */ int &Out_Len, int Out_StartIdx);
	void __fastcall Decrypt_Finalize(Sbtypes::ByteArray &OutBuf, /* out */ int &Out_Len, int Out_StartIdx);
	void __fastcall EncryptBuf(const Sbtypes::ByteArray InBuf, int In_StartIdx, int In_Len, Sbtypes::ByteArray &OutBuf, /* out */ int &Out_Len, int Out_StartIdx)/* overload */;
	void __fastcall EncryptBuf(const Sbtypes::ByteArray InBuf, Sbtypes::ByteArray &OutBuf)/* overload */;
	void __fastcall DecryptBuf(const Sbtypes::ByteArray InBuf, int In_StartIdx, int In_Len, Sbtypes::ByteArray &OutBuf, /* out */ int &Out_Len, int Out_StartIdx)/* overload */;
	void __fastcall DecryptBuf(const Sbtypes::ByteArray InBuf, Sbtypes::ByteArray &OutBuf)/* overload */;
	void __fastcall EncryptStream(Classes::TStream* Source, unsigned Count, Classes::TStream* Dest);
	void __fastcall DecryptStream(Classes::TStream* Source, unsigned Count, Classes::TStream* Dest);
	void __fastcall MAC_Block(void * InBuf, int In_Len)/* overload */;
	void __fastcall MAC_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx, int In_Len)/* overload */;
	void __fastcall MAC_Finalize(int Qnt_Bits, /* out */ Sbtypes::ByteArray &MAC);
	void __fastcall MAC_Stream(Classes::TStream* Source, unsigned Count, int Qnt_Bits, /* out */ Sbtypes::ByteArray &MAC);
	__property Sbtypes::ByteArray Key = {read=GetKey, write=SetKey};
	__property Sbtypes::ByteArray IV = {read=GetIV, write=SetIV};
	__property TElGOSTMode Mode = {read=fMode, write=fMode, nodefault};
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE Sbtypes::ByteArray __fastcall gost28147IMIT(const Sbtypes::ByteArray IV, const Sbtypes::ByteArray K, const Sbtypes::ByteArray D);
extern PACKAGE bool __fastcall KeyDiversifyCryptoPro(const Sbtypes::ByteArray UKM, const Sbtypes::ByteArray KEK, Sbtypes::ByteArray &DKEK, int &DKEKSize);
extern PACKAGE bool __fastcall KeyWrap28147(const Sbtypes::ByteArray UKM, const Sbtypes::ByteArray CEK, const Sbtypes::ByteArray KEK, Sbtypes::ByteArray &WCEK, int &WCEKSize, Sbtypes::ByteArray &CEK_MAC, int &CEKMACSize);
extern PACKAGE bool __fastcall KeyUnwrap28147(const Sbtypes::ByteArray UKM, const Sbtypes::ByteArray WCEK, const Sbtypes::ByteArray KEK, const Sbtypes::ByteArray CEK_MAC, Sbtypes::ByteArray &CEK, int &CEKSize);
extern PACKAGE bool __fastcall KeyWrapCryptoPro(const Sbtypes::ByteArray UKM, const Sbtypes::ByteArray CEK, const Sbtypes::ByteArray KEK, Sbtypes::ByteArray &WCEK, int &WCEKSize, Sbtypes::ByteArray &CEK_MAC, int &CEKMACSize);
extern PACKAGE bool __fastcall KeyUnwrapCryptoPro(const Sbtypes::ByteArray UKM, const Sbtypes::ByteArray WCEK, const Sbtypes::ByteArray KEK, const Sbtypes::ByteArray CEK_MAC, Sbtypes::ByteArray &CEK, int &CEKSize);

}	/* namespace Sbgost2814789 */
using namespace Sbgost2814789;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbgost2814789HPP
