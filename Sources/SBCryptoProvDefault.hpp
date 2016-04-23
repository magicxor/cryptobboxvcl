// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovdefault.pas' rev: 21.00

#ifndef SbcryptoprovdefaultHPP
#define SbcryptoprovdefaultHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltin.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovdefault
{
//-- type declarations -------------------------------------------------------
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE Sbcryptoprov::TElCustomCryptoProvider* __fastcall DefaultCryptoProvider(void);
extern PACKAGE void __fastcall SetDefaultCryptoProviderType(Sbcryptoprov::TElCustomCryptoProviderClass Value);

}	/* namespace Sbcryptoprovdefault */
using namespace Sbcryptoprovdefault;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovdefaultHPP
