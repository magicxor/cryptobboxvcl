// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbalgorithmidentifier.pas' rev: 21.00

#ifndef SbalgorithmidentifierHPP
#define SbalgorithmidentifierHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbalgorithmidentifier
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElAlgorithmIdentifier;
class PASCALIMPLEMENTATION TElAlgorithmIdentifier : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbtypes::ByteArray FAlgorithmOID;
	int FAlgorithm;
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual void __fastcall SetAlgorithm(int Value);
	virtual void __fastcall SetAlgorithmOID(const Sbtypes::ByteArray Value);
	virtual bool __fastcall GetIsSignatureAlgorithm(void);
	virtual bool __fastcall GetIsPublicKeyAlgorithm(void);
	virtual bool __fastcall GetIsEncryptionAlgorithm(void);
	virtual bool __fastcall GetIsHashAlgorithm(void);
	virtual int __fastcall GetSignatureHashAlgorithm(void);
	
public:
	__fastcall TElAlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
	virtual TElAlgorithmIdentifier* __fastcall Clone(void);
	HIDESBASE virtual bool __fastcall Equals(TElAlgorithmIdentifier* Algorithm)/* overload */;
	virtual bool __fastcall Equals(System::TObject* Obj)/* overload */;
	__classmethod TElAlgorithmIdentifier* __fastcall CreateFromBuffer(void * Buffer, int Size);
	__classmethod TElAlgorithmIdentifier* __fastcall CreateFromTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	__classmethod TElAlgorithmIdentifier* __fastcall CreateByAlgorithm(int Algorithm);
	__classmethod TElAlgorithmIdentifier* __fastcall CreateByAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual bool __fastcall IsAlgorithmSupported(int Algorithm);
	virtual void __fastcall LoadFromBuffer(void * Buffer, int Size);
	virtual void __fastcall SaveToBuffer(void * Buffer, int &Size);
	virtual void __fastcall LoadFromTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveToTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual Sbtypes::ByteArray __fastcall WriteParameters(void);
	__property Sbtypes::ByteArray AlgorithmOID = {read=FAlgorithmOID, write=SetAlgorithmOID};
	__property int Algorithm = {read=FAlgorithm, write=SetAlgorithm, nodefault};
	__property int SignatureHashAlgorithm = {read=GetSignatureHashAlgorithm, nodefault};
	__property bool IsSignatureAlgorithm = {read=GetIsSignatureAlgorithm, nodefault};
	__property bool IsPublicKeyAlgorithm = {read=GetIsPublicKeyAlgorithm, nodefault};
	__property bool IsEncryptionAlgorithm = {read=GetIsEncryptionAlgorithm, nodefault};
	__property bool IsHashAlgorithm = {read=GetIsHashAlgorithm, nodefault};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElAlgorithmIdentifier(void) { }
	
};


class DELPHICLASS TElRSAAlgorithmIdentifier;
class PASCALIMPLEMENTATION TElRSAAlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	int FHashAlgorithm;
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual void __fastcall SetAlgorithmOID(const Sbtypes::ByteArray Value);
	void __fastcall SetHashAlgorithm(int Value);
	virtual bool __fastcall GetIsSignatureAlgorithm(void);
	virtual bool __fastcall GetIsPublicKeyAlgorithm(void);
	virtual bool __fastcall GetIsEncryptionAlgorithm(void);
	virtual int __fastcall GetSignatureHashAlgorithm(void);
	
public:
	__fastcall TElRSAAlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
	__property int HashAlgorithm = {read=FHashAlgorithm, write=SetHashAlgorithm, nodefault};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElRSAAlgorithmIdentifier(void) { }
	
};


class DELPHICLASS TElRSAPSSAlgorithmIdentifier;
class PASCALIMPLEMENTATION TElRSAPSSAlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	int FHashAlgorithm;
	int FSaltSize;
	int FTrailerField;
	int FMGF;
	int FMGFHashAlgorithm;
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual bool __fastcall GetIsSignatureAlgorithm(void);
	virtual bool __fastcall GetIsPublicKeyAlgorithm(void);
	virtual bool __fastcall GetIsEncryptionAlgorithm(void);
	virtual int __fastcall GetSignatureHashAlgorithm(void);
	
public:
	__fastcall TElRSAPSSAlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
	__property int HashAlgorithm = {read=FHashAlgorithm, write=FHashAlgorithm, nodefault};
	__property int SaltSize = {read=FSaltSize, write=FSaltSize, nodefault};
	__property int TrailerField = {read=FTrailerField, write=FTrailerField, nodefault};
	__property int MGF = {read=FMGF, write=FMGF, nodefault};
	__property int MGFHashAlgorithm = {read=FMGFHashAlgorithm, write=FMGFHashAlgorithm, nodefault};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElRSAPSSAlgorithmIdentifier(void) { }
	
};


class DELPHICLASS TElRSAOAEPAlgorithmIdentifier;
class PASCALIMPLEMENTATION TElRSAOAEPAlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	int FHashAlgorithm;
	int FMGF;
	int FMGFHashAlgorithm;
	System::UnicodeString FStrLabel;
	bool FWriteDefaults;
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual bool __fastcall GetIsSignatureAlgorithm(void);
	virtual bool __fastcall GetIsPublicKeyAlgorithm(void);
	virtual bool __fastcall GetIsEncryptionAlgorithm(void);
	
public:
	__fastcall TElRSAOAEPAlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
	__property int HashAlgorithm = {read=FHashAlgorithm, write=FHashAlgorithm, nodefault};
	__property int MGF = {read=FMGF, write=FMGF, nodefault};
	__property int MGFHashAlgorithm = {read=FMGFHashAlgorithm, write=FMGFHashAlgorithm, nodefault};
	__property System::UnicodeString StrLabel = {read=FStrLabel, write=FStrLabel};
	__property bool WriteDefaults = {read=FWriteDefaults, write=FWriteDefaults, nodefault};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElRSAOAEPAlgorithmIdentifier(void) { }
	
};


class DELPHICLASS TElDSAAlgorithmIdentifier;
class PASCALIMPLEMENTATION TElDSAAlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	Sbtypes::ByteArray FP;
	Sbtypes::ByteArray FQ;
	Sbtypes::ByteArray FG;
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual bool __fastcall GetIsSignatureAlgorithm(void);
	virtual bool __fastcall GetIsPublicKeyAlgorithm(void);
	virtual bool __fastcall GetIsEncryptionAlgorithm(void);
	virtual int __fastcall GetSignatureHashAlgorithm(void);
	void __fastcall SetP(const Sbtypes::ByteArray V);
	void __fastcall SetQ(const Sbtypes::ByteArray V);
	void __fastcall SetG(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElDSAAlgorithmIdentifier(void);
	__fastcall virtual ~TElDSAAlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
	__property Sbtypes::ByteArray P = {read=FP, write=SetP};
	__property Sbtypes::ByteArray Q = {read=FQ, write=SetQ};
	__property Sbtypes::ByteArray G = {read=FG, write=SetG};
};


class DELPHICLASS TElDHAlgorithmIdentifier;
class PASCALIMPLEMENTATION TElDHAlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	Sbtypes::ByteArray FP;
	Sbtypes::ByteArray FQ;
	Sbtypes::ByteArray FG;
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual bool __fastcall GetIsSignatureAlgorithm(void);
	virtual bool __fastcall GetIsPublicKeyAlgorithm(void);
	virtual bool __fastcall GetIsEncryptionAlgorithm(void);
	void __fastcall SetP(const Sbtypes::ByteArray V);
	void __fastcall SetQ(const Sbtypes::ByteArray V);
	void __fastcall SetG(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElDHAlgorithmIdentifier(void);
	__fastcall virtual ~TElDHAlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
	__property Sbtypes::ByteArray P = {read=FP, write=SetP};
	__property Sbtypes::ByteArray Q = {read=FQ, write=SetQ};
	__property Sbtypes::ByteArray G = {read=FG, write=SetG};
};


class DELPHICLASS TElECAlgorithmIdentifier;
class PASCALIMPLEMENTATION TElECAlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	int FVersion;
	Sbtypes::ByteArray FCurve;
	Sbtypes::ByteArray FFieldID;
	int FFieldType;
	Sbtypes::ByteArray FBasis;
	int FM;
	int FK1;
	int FK2;
	int FK3;
	int FHashAlgorithm;
	bool FSpecifiedCurve;
	bool FCompressPoints;
	bool FHybridPoints;
	bool FImplicitCurve;
	Sbtypes::ByteArray FSeed;
	Sbtypes::ByteArray FP;
	Sbtypes::ByteArray FN;
	int FH;
	Sbtypes::ByteArray FA;
	Sbtypes::ByteArray FB;
	Sbtypes::ByteArray FX;
	Sbtypes::ByteArray FY;
	Sbtypes::ByteArray FBase;
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual bool __fastcall GetIsSignatureAlgorithm(void);
	virtual bool __fastcall GetIsPublicKeyAlgorithm(void);
	virtual bool __fastcall GetIsEncryptionAlgorithm(void);
	void __fastcall SetCurve(const Sbtypes::ByteArray V);
	void __fastcall SetFieldID(const Sbtypes::ByteArray V);
	void __fastcall SetBasis(const Sbtypes::ByteArray V);
	void __fastcall SetSeed(const Sbtypes::ByteArray V);
	void __fastcall SetP(const Sbtypes::ByteArray V);
	void __fastcall SetN(const Sbtypes::ByteArray V);
	void __fastcall SetA(const Sbtypes::ByteArray V);
	void __fastcall SetB(const Sbtypes::ByteArray V);
	void __fastcall SetX(const Sbtypes::ByteArray V);
	void __fastcall SetY(const Sbtypes::ByteArray V);
	void __fastcall SetBase(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElECAlgorithmIdentifier(void);
	__fastcall virtual ~TElECAlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
	__property int Version = {read=FVersion, write=FVersion, nodefault};
	__property Sbtypes::ByteArray Curve = {read=FCurve, write=SetCurve};
	__property Sbtypes::ByteArray FieldID = {read=FFieldID, write=SetFieldID};
	__property int FieldType = {read=FFieldType, write=FFieldType, nodefault};
	__property Sbtypes::ByteArray Basis = {read=FBasis, write=SetBasis};
	__property int M = {read=FM, write=FM, nodefault};
	__property int K1 = {read=FK1, write=FK1, nodefault};
	__property int K2 = {read=FK2, write=FK2, nodefault};
	__property int K3 = {read=FK3, write=FK3, nodefault};
	__property int HashAlgorithm = {read=FHashAlgorithm, write=FHashAlgorithm, nodefault};
	__property bool SpecifiedCurve = {read=FSpecifiedCurve, write=FSpecifiedCurve, nodefault};
	__property bool CompressPoints = {read=FCompressPoints, write=FCompressPoints, nodefault};
	__property bool HybridPoints = {read=FHybridPoints, write=FHybridPoints, nodefault};
	__property bool ImplicitCurve = {read=FImplicitCurve, write=FImplicitCurve, nodefault};
	__property Sbtypes::ByteArray Seed = {read=FSeed, write=SetSeed};
	__property Sbtypes::ByteArray P = {read=FP, write=SetP};
	__property Sbtypes::ByteArray N = {read=FN, write=SetN};
	__property int H = {read=FH, write=FH, nodefault};
	__property Sbtypes::ByteArray A = {read=FA, write=SetA};
	__property Sbtypes::ByteArray B = {read=FB, write=SetB};
	__property Sbtypes::ByteArray X = {read=FX, write=SetX};
	__property Sbtypes::ByteArray Y = {read=FY, write=SetY};
	__property Sbtypes::ByteArray Base = {read=FBase, write=SetBase};
};


class DELPHICLASS TElECDSAAlgorithmIdentifier;
class PASCALIMPLEMENTATION TElECDSAAlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	int FHashAlgorithm;
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual void __fastcall SetAlgorithmOID(const Sbtypes::ByteArray Value);
	void __fastcall SetHashAlgorithm(int Value);
	virtual bool __fastcall GetIsSignatureAlgorithm(void);
	virtual bool __fastcall GetIsPublicKeyAlgorithm(void);
	virtual bool __fastcall GetIsEncryptionAlgorithm(void);
	virtual int __fastcall GetSignatureHashAlgorithm(void);
	
public:
	__fastcall TElECDSAAlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
	__property int HashAlgorithm = {read=FHashAlgorithm, write=SetHashAlgorithm, nodefault};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElECDSAAlgorithmIdentifier(void) { }
	
};


class DELPHICLASS TElGOST3411AlgorithmIdentifier;
class PASCALIMPLEMENTATION TElGOST3411AlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual void __fastcall SetAlgorithmOID(const Sbtypes::ByteArray Value);
	virtual bool __fastcall GetIsHashAlgorithm(void);
	
public:
	__fastcall TElGOST3411AlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElGOST3411AlgorithmIdentifier(void) { }
	
};


class DELPHICLASS TElGOST3410AlgorithmIdentifier;
class PASCALIMPLEMENTATION TElGOST3410AlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	Sbtypes::ByteArray FPublicKeyParamSet;
	Sbtypes::ByteArray FDigestParamSet;
	Sbtypes::ByteArray FEncryptionParamSet;
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual void __fastcall SetAlgorithmOID(const Sbtypes::ByteArray Value);
	virtual bool __fastcall GetIsPublicKeyAlgorithm(void);
	void __fastcall SetPublicKeyParamSet(const Sbtypes::ByteArray V);
	void __fastcall SetDigestParamSet(const Sbtypes::ByteArray V);
	void __fastcall SetEncryptionParamSet(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElGOST3410AlgorithmIdentifier(void);
	__fastcall virtual ~TElGOST3410AlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
	__property Sbtypes::ByteArray PublicKeyParamSet = {read=FPublicKeyParamSet, write=SetPublicKeyParamSet};
	__property Sbtypes::ByteArray DigestParamSet = {read=FDigestParamSet, write=SetDigestParamSet};
	__property Sbtypes::ByteArray EncryptionParamSet = {read=FEncryptionParamSet, write=SetEncryptionParamSet};
};


class DELPHICLASS TElGOST3411WithGOST3410AlgorithmIdentifier;
class PASCALIMPLEMENTATION TElGOST3411WithGOST3410AlgorithmIdentifier : public TElAlgorithmIdentifier
{
	typedef TElAlgorithmIdentifier inherited;
	
private:
	virtual void __fastcall LoadParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual void __fastcall SaveParameters(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	virtual bool __fastcall CheckAlgorithmOID(const Sbtypes::ByteArray OID);
	virtual bool __fastcall GetIsSignatureAlgorithm(void);
	virtual int __fastcall GetSignatureHashAlgorithm(void);
	
public:
	__fastcall TElGOST3411WithGOST3410AlgorithmIdentifier(void);
	virtual void __fastcall Assign(TElAlgorithmIdentifier* Source);
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElGOST3411WithGOST3410AlgorithmIdentifier(void) { }
	
};


class DELPHICLASS EElAlgorithmIdentifierError;
class PASCALIMPLEMENTATION EElAlgorithmIdentifierError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElAlgorithmIdentifierError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElAlgorithmIdentifierError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElAlgorithmIdentifierError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElAlgorithmIdentifierError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElAlgorithmIdentifierError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElAlgorithmIdentifierError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElAlgorithmIdentifierError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElAlgorithmIdentifierError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElAlgorithmIdentifierError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbalgorithmidentifier */
using namespace Sbalgorithmidentifier;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbalgorithmidentifierHPP
