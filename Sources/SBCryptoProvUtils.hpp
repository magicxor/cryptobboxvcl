// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovutils.pas' rev: 21.00

#ifndef SbcryptoprovutilsHPP
#define SbcryptoprovutilsHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovutils
{
//-- type declarations -------------------------------------------------------
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE bool __fastcall CryptoProvGetBoolParam(Sbrdn::TElRelativeDistinguishedName* Params, const Sbtypes::ByteArray Name, bool Default);
extern PACKAGE int __fastcall GetIntegerPropFromBuffer(const Sbtypes::ByteArray Value, int Default = 0x0);
extern PACKAGE __int64 __fastcall GetInt64PropFromBuffer(const Sbtypes::ByteArray Value, int Default = 0x0);
extern PACKAGE Sbtypes::ByteArray __fastcall GetBufferFromInteger(int Value);
extern PACKAGE Sbtypes::ByteArray __fastcall GetBufferFromInt64(__int64 Value);
extern PACKAGE bool __fastcall GetBoolFromBuffer(const Sbtypes::ByteArray Value, bool Default = false);
extern PACKAGE Sbtypes::ByteArray __fastcall GetBufferFromBool(bool Value);
extern PACKAGE void * __fastcall GetPointerFromBuffer(const Sbtypes::ByteArray Value);
extern PACKAGE Sbtypes::ByteArray __fastcall GetBufferFromPointer(void * Value);
extern PACKAGE bool __fastcall ExtractSymmetricCipherParams(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int &KeyLen, Sbtypes::ByteArray &IV);
extern PACKAGE Sbtypes::ByteArray __fastcall SerializeParams(Sbrdn::TElRelativeDistinguishedName* Params);
extern PACKAGE Sbrdn::TElRelativeDistinguishedName* __fastcall UnserializeParams(void * Buffer, int Size);
extern PACKAGE bool __fastcall IsKeyDrivenOperation(int OpType);
extern PACKAGE bool __fastcall IsSecretKeyOperation(int OpType);
extern PACKAGE bool __fastcall IsAlgorithmIndependentOperation(int OpType);

}	/* namespace Sbcryptoprovutils */
using namespace Sbcryptoprovutils;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovutilsHPP
