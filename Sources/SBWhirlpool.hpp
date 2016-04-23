// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbwhirlpool.pas' rev: 21.00

#ifndef SbwhirlpoolHPP
#define SbwhirlpoolHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbwhirlpool
{
//-- type declarations -------------------------------------------------------
#pragma pack(push,1)
struct TWhirlpoolContext
{
	
public:
	Sbtypes::ByteArray BitsHashed;
	Sbtypes::ByteArray Buffer;
	unsigned BufferSize;
	Sbtypes::Int64Array State;
};
#pragma pack(pop)


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall InitializeWhirlpool(TWhirlpoolContext &Context);
extern PACKAGE void __fastcall HashWhirlpool(TWhirlpoolContext &Context, void * Chunk, unsigned ChunkSize)/* overload */;
extern PACKAGE void __fastcall HashWhirlpool(TWhirlpoolContext &Context, Sbtypes::ByteArray Chunk, unsigned ChunkOffset, unsigned ChunkSize)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest512 __fastcall FinalizeWhirlpool(TWhirlpoolContext &Context);

}	/* namespace Sbwhirlpool */
using namespace Sbwhirlpool;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbwhirlpoolHPP
