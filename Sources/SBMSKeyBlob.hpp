// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbmskeyblob.pas' rev: 21.00

#ifndef SbmskeyblobHPP
#define SbmskeyblobHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbalgorithmidentifier.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbgost2814789.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbmskeyblob
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS EElMSKeyBlobError;
class PASCALIMPLEMENTATION EElMSKeyBlobError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElMSKeyBlobError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElMSKeyBlobError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElMSKeyBlobError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElMSKeyBlobError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElMSKeyBlobError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElMSKeyBlobError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElMSKeyBlobError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElMSKeyBlobError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElMSKeyBlobError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const int SB_MSKEYBLOB_ERROR_UNSUPPORTED_BLOB_TYPE = 8449;
static const int SB_MSKEYBLOB_ERROR_INVALID_FORMAT = 8450;
static const int SB_MSKEYBLOB_ERROR_UNSUPPORTED_VERSION = 8451;
static const int SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL = 8452;
static const int SB_MSKEYBLOB_ERROR_NO_PRIVATE_KEY = 8453;
static const int SB_MSKEYBLOB_ERROR_UNSUPPORTED_ALGORITHM = 8454;
static const ShortInt SB_KEY_BLOB_RSA = 0x1;
static const ShortInt SB_KEY_BLOB_DSS = 0x2;
extern PACKAGE bool __fastcall WriteMSKeyBlobEx(void * Buffer, int Size, void * OutBuffer, int &OutSize, Sbalgorithmidentifier::TElAlgorithmIdentifier* Algorithm);
extern PACKAGE int __fastcall ParseMSKeyBlob(void * Buffer, int Size, void * OutBuffer, int &OutSize, /* out */ int &BlobType);
extern PACKAGE bool __fastcall WriteMSKeyBlob(void * Buffer, int Size, void * OutBuffer, int &OutSize, System::Byte BlobType);
extern PACKAGE bool __fastcall WriteMSPublicKeyBlob(void * Buffer, int Size, void * OutBuffer, int &OutSize, int BlobType);
extern PACKAGE bool __fastcall WriteMSDSSPublicKeyBlob(void * P, int PSize, void * Q, int QSize, void * G, int GSize, void * Y, int YSize, void * OutBuffer, int &OutSize);

}	/* namespace Sbmskeyblob */
using namespace Sbmskeyblob;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbmskeyblobHPP
