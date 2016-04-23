// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sblicensemanager.pas' rev: 21.00

#ifndef SblicensemanagerHPP
#define SblicensemanagerHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sblicensemanager
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBLicenseKeyRegKey { rkHK };
#pragma option pop

class DELPHICLASS TElSBLicenseManager;
class PASCALIMPLEMENTATION TElSBLicenseManager : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
private:
	System::UnicodeString FLicenseKey;
	System::UnicodeString FLicenseKeyFile;
	HKEY FRegistryKey;
	void __fastcall SetLicenseKey(const System::UnicodeString Value);
	void __fastcall SetLicenseKeyFile(const System::UnicodeString Value);
	void __fastcall SetRegistryKey(HKEY Value);
	
public:
	__fastcall virtual TElSBLicenseManager(Classes::TComponent* AOwner);
	__fastcall virtual ~TElSBLicenseManager(void);
	__property HKEY RegistryKey = {read=FRegistryKey, write=SetRegistryKey, nodefault};
	
__published:
	__property System::UnicodeString LicenseKey = {read=FLicenseKey, write=SetLicenseKey};
	__property System::UnicodeString LicenseKeyFile = {read=FLicenseKeyFile, write=SetLicenseKeyFile};
};


typedef TElSBLicenseManager ElSBLicenseManager;

//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall Register(void);

}	/* namespace Sblicensemanager */
using namespace Sblicensemanager;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SblicensemanagerHPP
