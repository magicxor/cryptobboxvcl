// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Cryptobboxdx.pas' rev: 21.00

#ifndef CryptobboxdxHPP
#define CryptobboxdxHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sblicensemanager.hpp>	// Pascal unit
#include <Sbalgorithmidentifier.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbstreams.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbdes.hpp>	// Pascal unit
#include <Sbmd.hpp>	// Pascal unit
#include <Sbsha.hpp>	// Pascal unit
#include <Sbsha2.hpp>	// Pascal unit
#include <Sbhmac.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbrc2.hpp>	// Pascal unit
#include <Sbrc4.hpp>	// Pascal unit
#include <Sbaes.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbpem.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbwincrypt.hpp>	// Pascal unit
#include <Sbripemd.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbblowfish.hpp>	// Pascal unit
#include <Sbtwofish.hpp>	// Pascal unit
#include <Sbcast128.hpp>	// Pascal unit
#include <Sbcamellia.hpp>	// Pascal unit
#include <Sbcrc.hpp>	// Pascal unit
#include <Sbserpent.hpp>	// Pascal unit
#include <Sbsocket.hpp>	// Pascal unit
#include <Sbelgamal.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbcustomcrypto.hpp>	// Pascal unit
#include <Sbzcommonunit.hpp>	// Pascal unit
#include <Sbzcompressunit.hpp>	// Pascal unit
#include <Sbzuncompressunit.hpp>	// Pascal unit
#include <Sbzlib.hpp>	// Pascal unit
#include <Sbrabbit.hpp>	// Pascal unit
#include <Sbseed.hpp>	// Pascal unit
#include <Sbtimer.hpp>	// Pascal unit
#include <Sbcmsutils.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcryptoprovrs.hpp>	// Pascal unit
#include <Sbcryptoprovutils.hpp>	// Pascal unit
#include <Sbcryptoprovdefault.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltin.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltinhash.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltinpki.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltinsym.hpp>	// Pascal unit
#include <Sbcryptoprovwin32.hpp>	// Pascal unit
#include <Sbcryptoprovmanager.hpp>	// Pascal unit
#include <Sbmskeyblob.hpp>	// Pascal unit
#include <Sbrsa.hpp>	// Pascal unit
#include <Sbdsa.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbpkcs8.hpp>	// Pascal unit
#include <Sbpkcs5.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbcrl.hpp>	// Pascal unit
#include <Sbcrlstorage.hpp>	// Pascal unit
#include <Sbcertretriever.hpp>	// Pascal unit
#include <Sbcertvalidator.hpp>	// Pascal unit
#include <Sbjks.hpp>	// Pascal unit
#include <Sbpublickeycrypto.hpp>	// Pascal unit
#include <Sbsymmetriccrypto.hpp>	// Pascal unit
#include <Sbocspcommon.hpp>	// Pascal unit
#include <Sbocspclient.hpp>	// Pascal unit
#include <Sbocspstorage.hpp>	// Pascal unit
#include <Sbpkiasync.hpp>	// Pascal unit
#include <Sbpkicommon.hpp>	// Pascal unit
#include <Sbtspcommon.hpp>	// Pascal unit
#include <Sbtspclient.hpp>	// Pascal unit
#include <Sbsockettspclient.hpp>	// Pascal unit
#include <Sbpkcs7.hpp>	// Pascal unit
#include <Sbpkcs7utils.hpp>	// Pascal unit
#include <Sbpkcs12.hpp>	// Pascal unit
#include <Sbmessages.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit
#include <Sbwincertstorage.hpp>	// Pascal unit
#include <Sbsrp.hpp>	// Pascal unit
#include <Sbsmimesignatures.hpp>	// Pascal unit
#include <Sbumac.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbeccommon.hpp>	// Pascal unit
#include <Sbecmath.hpp>	// Pascal unit
#include <Sbecdsa.hpp>	// Pascal unit
#include <Sbgostcommon.hpp>	// Pascal unit
#include <Sbgost341194.hpp>	// Pascal unit
#include <Sbgost341094.hpp>	// Pascal unit
#include <Sbgost341001.hpp>	// Pascal unit
#include <Sbgost2814789.hpp>	// Pascal unit
#include <Sbpunycode.hpp>	// Pascal unit
#include <Sbsasl.hpp>	// Pascal unit
#include <Sbhttpsconstants.hpp>	// Pascal unit
#include <Sbhttpauth.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltinex.hpp>	// Pascal unit
#include <Sbidea.hpp>	// Pascal unit
#include <Sbbcrypt.hpp>	// Pascal unit
#include <Sbwhirlpool.hpp>	// Pascal unit
#include <Sbunicode.hpp>	// Pascal unit
#include <Sbchsclasses.hpp>	// Pascal unit
#include <Sbchsconv.hpp>	// Pascal unit
#include <Sbchsconvbase.hpp>	// Pascal unit
#include <Sbchsconvcharsets.hpp>	// Pascal unit
#include <Sbchsconvconsts.hpp>	// Pascal unit
#include <Variants.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Varutils.hpp>	// Pascal unit
#include <Typinfo.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Timespan.hpp>	// Pascal unit
#include <Syncobjs.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Cryptobboxdx
{
//-- type declarations -------------------------------------------------------
//-- var, const, procedure ---------------------------------------------------

}	/* namespace Cryptobboxdx */
using namespace Cryptobboxdx;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// CryptobboxdxHPP
