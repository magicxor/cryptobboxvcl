// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbgost341194.pas' rev: 21.00

#ifndef Sbgost341194HPP
#define Sbgost341194HPP

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

namespace Sbgost341194
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElGOSTMD;
class PASCALIMPLEMENTATION TElGOSTMD : public Sbgostcommon::TElGOSTBase
{
	typedef Sbgostcommon::TElGOSTBase inherited;
	
protected:
	Sbtypes::ByteArray fH;
	Sbtypes::ByteArray fS;
	Sbtypes::ByteArray fM;
	Sbtypes::ByteArray fU;
	Sbtypes::ByteArray fV;
	Sbtypes::ByteArray fW;
	Sbtypes::ByteArray fTmp;
	Sbtypes::ByteArray fSum;
	__int64 fTotalLen;
	__classmethod virtual unsigned __fastcall GetBlockSize();
	void __fastcall Hash_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx);
	HIDESBASE void __fastcall Process_Block(const Sbtypes::ByteArray InBuf, int In_StartIdx);
	
public:
	__classmethod int __fastcall DigestSize();
	__fastcall TElGOSTMD(void)/* overload */;
	__fastcall TElGOSTMD(StaticArray<System::Byte, 16> const *SubstBlock)/* overload */;
	__fastcall virtual ~TElGOSTMD(void);
	virtual void __fastcall Reset(void);
	virtual void __fastcall Clone(Sbgostcommon::TElGOSTBase* Source);
	void __fastcall Update(void * In_Buf, unsigned Len)/* overload */;
	void __fastcall Update(const Sbtypes::ByteArray In_Buf, unsigned StartIndex, unsigned Len)/* overload */;
	void __fastcall Final(/* out */ Sbtypes::ByteArray &Digest);
	void __fastcall Calculate(const Sbtypes::ByteArray In_Buf, unsigned StartIndex, unsigned Len, /* out */ Sbtypes::ByteArray &Digest)/* overload */;
	void __fastcall Calculate(Classes::TStream* Source, unsigned Count, /* out */ Sbtypes::ByteArray &Digest)/* overload */;
};


//-- var, const, procedure ---------------------------------------------------
static const ShortInt c_GOST_DigestSize = 0x20;

}	/* namespace Sbgost341194 */
using namespace Sbgost341194;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbgost341194HPP
