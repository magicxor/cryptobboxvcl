// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcmsutils.pas' rev: 21.00

#ifndef SbcmsutilsHPP
#define SbcmsutilsHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcmsutils
{
//-- type declarations -------------------------------------------------------
typedef void __fastcall (__closure *TSBCMSCertificateNeededEvent)(System::TObject* Sender, Sbcustomcertstorage::TElCertificateLookup* Lookup, Sbx509::TElX509Certificate* &Cert);

//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbcmsutils */
using namespace Sbcmsutils;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcmsutilsHPP
