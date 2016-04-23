// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbtwofish.pas' rev: 21.00

#ifndef SbtwofishHPP
#define SbtwofishHPP

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

namespace Sbtwofish
{
//-- type declarations -------------------------------------------------------
struct TTwofishExpandedKey
{
	
public:
	StaticArray<unsigned, 40> ExpandedKey;
	StaticArray<unsigned, 4> SBoxKey;
	StaticArray<System::Byte, 256> SBox0;
	StaticArray<System::Byte, 256> SBox1;
	StaticArray<System::Byte, 256> SBox2;
	StaticArray<System::Byte, 256> SBox3;
	int KeyLen;
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall EncryptBlock(const TTwofishExpandedKey &ExpandedKey, unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3);
extern PACKAGE void __fastcall DecryptBlock(const TTwofishExpandedKey &ExpandedKey, unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3);
extern PACKAGE void __fastcall ExpandKey(const Sbtypes::ByteArray Key, TTwofishExpandedKey &ExpandedKey);

}	/* namespace Sbtwofish */
using namespace Sbtwofish;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbtwofishHPP
