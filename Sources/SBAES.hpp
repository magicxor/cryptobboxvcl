// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbaes.pas' rev: 21.00

#ifndef SbaesHPP
#define SbaesHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbaes
{
//-- type declarations -------------------------------------------------------
typedef StaticArray<System::Byte, 16> TAESBuffer;

typedef TAESBuffer *PAESBuffer;

typedef StaticArray<System::Byte, 16> TAESKey128;

typedef StaticArray<unsigned, 44> TAESExpandedKey128;

typedef TAESKey128 *PAESKey128;

typedef TAESExpandedKey128 *PAESExpandedKey128;

typedef StaticArray<System::Byte, 24> TAESKey192;

typedef StaticArray<unsigned, 54> TAESExpandedKey192;

typedef TAESKey192 *PAESKey192;

typedef TAESExpandedKey192 *PAESExpandedKey192;

typedef StaticArray<System::Byte, 32> TAESKey256;

typedef StaticArray<unsigned, 64> TAESExpandedKey256;

typedef TAESKey256 *PAESKey256;

typedef TAESExpandedKey256 *PAESExpandedKey256;

//-- var, const, procedure ---------------------------------------------------
static const ShortInt TAESBufferSize = 0x10;
extern PACKAGE void __fastcall ExpandKeyForEncryption128(System::Byte const *Key, /* out */ unsigned *ExpandedKey)/* overload */;
extern PACKAGE void __fastcall ExpandKeyForEncryption192(System::Byte const *Key, /* out */ unsigned *ExpandedKey)/* overload */;
extern PACKAGE void __fastcall ExpandKeyForEncryption256(System::Byte const *Key, /* out */ unsigned *ExpandedKey)/* overload */;
extern PACKAGE void __fastcall ExpandKeyForDecryption128(unsigned *ExpandedKey)/* overload */;
extern PACKAGE void __fastcall ExpandKeyForDecryption192(unsigned *ExpandedKey)/* overload */;
extern PACKAGE void __fastcall ExpandKeyForDecryption256(unsigned *ExpandedKey)/* overload */;
extern PACKAGE void __fastcall Encrypt128(System::Byte const *InBuf, unsigned const *Key, /* out */ System::Byte *OutBuf)/* overload */;
extern PACKAGE void __fastcall Encrypt192(System::Byte const *InBuf, unsigned const *Key, /* out */ System::Byte *OutBuf)/* overload */;
extern PACKAGE void __fastcall Encrypt256(System::Byte const *InBuf, unsigned const *Key, /* out */ System::Byte *OutBuf)/* overload */;
extern PACKAGE void __fastcall Decrypt128(System::Byte const *InBuf, unsigned const *Key, /* out */ System::Byte *OutBuf)/* overload */;
extern PACKAGE void __fastcall Decrypt192(System::Byte const *InBuf, unsigned const *Key, /* out */ System::Byte *OutBuf)/* overload */;
extern PACKAGE void __fastcall Decrypt256(System::Byte const *InBuf, unsigned const *Key, /* out */ System::Byte *OutBuf)/* overload */;
extern PACKAGE void __fastcall Encrypt128(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, unsigned const *Key)/* overload */;
extern PACKAGE void __fastcall Encrypt192(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, unsigned const *Key)/* overload */;
extern PACKAGE void __fastcall Encrypt256(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, unsigned const *Key)/* overload */;
extern PACKAGE void __fastcall Decrypt128(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, unsigned const *Key)/* overload */;
extern PACKAGE void __fastcall Decrypt192(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, unsigned const *Key)/* overload */;
extern PACKAGE void __fastcall Decrypt256(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, unsigned const *Key)/* overload */;

}	/* namespace Sbaes */
using namespace Sbaes;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbaesHPP
