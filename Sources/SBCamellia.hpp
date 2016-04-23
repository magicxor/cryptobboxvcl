// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcamellia.pas' rev: 21.00

#ifndef SbcamelliaHPP
#define SbcamelliaHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcamellia
{
//-- type declarations -------------------------------------------------------
typedef StaticArray<unsigned, 2> TCmInt64;

typedef StaticArray<unsigned, 4> TCmInt128;

typedef StaticArray<System::Byte, 16> TSBCamelliaBuffer;

typedef TSBCamelliaBuffer *PSBCamelliaBuffer;

typedef Sbtypes::ByteArray TSBCamelliaKey;

struct TSBCamelliaExpandedKey
{
	
public:
	StaticArray<StaticArray<unsigned, 2>, 24> K;
	StaticArray<StaticArray<unsigned, 2>, 6> KE;
	StaticArray<StaticArray<unsigned, 2>, 4> KW;
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall EncryptBlock(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, const TSBCamelliaExpandedKey &Key, bool LongKey);
extern PACKAGE bool __fastcall ExpandKeyForEncryption(const Sbtypes::ByteArray Key, /* out */ TSBCamelliaExpandedKey &EKey);
extern PACKAGE bool __fastcall ExpandKeyForDecryption(const Sbtypes::ByteArray Key, /* out */ TSBCamelliaExpandedKey &EKey);

}	/* namespace Sbcamellia */
using namespace Sbcamellia;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcamelliaHPP
