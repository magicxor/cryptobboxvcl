// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovmanager.pas' rev: 21.00

#ifndef SbcryptoprovmanagerHPP
#define SbcryptoprovmanagerHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovmanager
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBCryptoEngineType { cetDefault, cetFIPS, cetCustom };
#pragma option pop

class DELPHICLASS TElBuiltInCryptoProviderManager;
class PASCALIMPLEMENTATION TElBuiltInCryptoProviderManager : public Sbcryptoprov::TElCustomCryptoProviderManager
{
	typedef Sbcryptoprov::TElCustomCryptoProviderManager inherited;
	
private:
	TSBCryptoEngineType FEngineType;
	Sbcryptoprov::TElCustomCryptoProvider* __fastcall GetBuiltInCryptoProvider(void);
	Sbcryptoprov::TElCustomCryptoProvider* __fastcall GetWin32CryptoProvider(void);
	void __fastcall SetEngineType(TSBCryptoEngineType Value);
	
public:
	virtual void __fastcall Init(void);
	virtual void __fastcall Deinit(void);
	virtual bool __fastcall IsProviderAllowed(Sbcryptoprov::TElCustomCryptoProvider* Prov);
	__property TSBCryptoEngineType EngineType = {read=FEngineType, write=SetEngineType, nodefault};
	__property Sbcryptoprov::TElCustomCryptoProvider* BuiltInCryptoProvider = {read=GetBuiltInCryptoProvider};
	__property Sbcryptoprov::TElCustomCryptoProvider* Win32CryptoProvider = {read=GetWin32CryptoProvider};
public:
	/* TElCustomCryptoProviderManager.Create */ inline __fastcall virtual TElBuiltInCryptoProviderManager(Classes::TComponent* AOwner) : Sbcryptoprov::TElCustomCryptoProviderManager(AOwner) { }
	/* TElCustomCryptoProviderManager.Destroy */ inline __fastcall virtual ~TElBuiltInCryptoProviderManager(void) { }
	
};


class DELPHICLASS TElFIPSCompliantCryptoProviderManager;
class PASCALIMPLEMENTATION TElFIPSCompliantCryptoProviderManager : public Sbcryptoprov::TElCustomCryptoProviderManager
{
	typedef Sbcryptoprov::TElCustomCryptoProviderManager inherited;
	
protected:
	Sbcryptoprov::TElCustomCryptoProvider* FFIPSCompliantCryptoProvider;
	
public:
	virtual void __fastcall Init(void);
	virtual void __fastcall Deinit(void);
	virtual bool __fastcall IsProviderAllowed(Sbcryptoprov::TElCustomCryptoProvider* Prov);
public:
	/* TElCustomCryptoProviderManager.Create */ inline __fastcall virtual TElFIPSCompliantCryptoProviderManager(Classes::TComponent* AOwner) : Sbcryptoprov::TElCustomCryptoProviderManager(AOwner) { }
	/* TElCustomCryptoProviderManager.Destroy */ inline __fastcall virtual ~TElFIPSCompliantCryptoProviderManager(void) { }
	
};


class DELPHICLASS EElCryptoProviderManagerError;
class PASCALIMPLEMENTATION EElCryptoProviderManagerError : public Sbcryptoprov::EElCryptoProviderError
{
	typedef Sbcryptoprov::EElCryptoProviderError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElCryptoProviderManagerError(const System::UnicodeString AMessage)/* overload */ : Sbcryptoprov::EElCryptoProviderError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElCryptoProviderManagerError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbcryptoprov::EElCryptoProviderError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElCryptoProviderManagerError(int Ident)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElCryptoProviderManagerError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElCryptoProviderManagerError(const System::UnicodeString Msg, int AHelpContext) : Sbcryptoprov::EElCryptoProviderError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElCryptoProviderManagerError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbcryptoprov::EElCryptoProviderError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElCryptoProviderManagerError(int Ident, int AHelpContext)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElCryptoProviderManagerError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbcryptoprov::EElCryptoProviderError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElCryptoProviderManagerError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE TElBuiltInCryptoProviderManager* __fastcall DefaultCryptoProviderManager(void);
extern PACKAGE TElFIPSCompliantCryptoProviderManager* __fastcall FIPSCompliantCryptoProviderManager(void);

}	/* namespace Sbcryptoprovmanager */
using namespace Sbcryptoprovmanager;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovmanagerHPP
