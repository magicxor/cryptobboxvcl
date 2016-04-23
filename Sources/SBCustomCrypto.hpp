// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcustomcrypto.pas' rev: 21.00

#ifndef SbcustomcryptoHPP
#define SbcustomcryptoHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcustomcrypto
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElKeyMaterial;
class PASCALIMPLEMENTATION TElKeyMaterial : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbcryptoprov::TElCustomCryptoKey* FKey;
	virtual bool __fastcall GetValid(void);
	virtual int __fastcall GetBits(void);
	virtual bool __fastcall GetExportable(void);
	virtual int __fastcall GetAlgorithm(void);
	Sbtypes::ByteArray __fastcall GetKeyID(void);
	void __fastcall SetKeyID(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetKeySubject(void);
	void __fastcall SetKeySubject(const Sbtypes::ByteArray Value);
	System::UnicodeString __fastcall GetProviderName(void);
	void __fastcall SetProviderName(const System::UnicodeString Value);
	
public:
	__fastcall TElKeyMaterial(void);
	__fastcall virtual ~TElKeyMaterial(void);
	virtual void __fastcall Generate(int Bits);
	virtual void __fastcall Save(Classes::TStream* Stream);
	virtual void __fastcall Load(Classes::TStream* Stream, int Count = 0x0);
	virtual void __fastcall Assign(TElKeyMaterial* Source);
	HIDESBASE virtual bool __fastcall Equals(TElKeyMaterial* Source, bool PublicOnly)/* overload */;
	virtual bool __fastcall Equals(System::TObject* Obj)/* overload */;
	virtual TElKeyMaterial* __fastcall Clone(void);
	virtual void __fastcall AssignCryptoKey(Sbcryptoprov::TElCustomCryptoKey* Key);
	virtual void __fastcall Persistentiate(void);
	__property bool Exportable = {read=GetExportable, nodefault};
	__property bool Valid = {read=GetValid, nodefault};
	__property int Bits = {read=GetBits, nodefault};
	__property Sbcryptoprov::TElCustomCryptoKey* Key = {read=FKey};
	__property int Algorithm = {read=GetAlgorithm, nodefault};
	__property Sbtypes::ByteArray KeyID = {read=GetKeyID, write=SetKeyID};
	__property Sbtypes::ByteArray KeySubject = {read=GetKeySubject, write=SetKeySubject};
	__property System::UnicodeString ProviderName = {read=GetProviderName, write=SetProviderName};
};

typedef TElKeyMaterial ElKeyMaterial
class DELPHICLASS TElCustomCrypto;
class PASCALIMPLEMENTATION TElCustomCrypto : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	/* TObject.Create */ inline __fastcall TElCustomCrypto(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TElCustomCrypto(void) { }
	
};

typedef TElCustomCrypto ElCustomCrypto
//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbcustomcrypto */
using namespace Sbcustomcrypto;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcustomcryptoHPP
