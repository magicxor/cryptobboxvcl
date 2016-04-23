// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpkicommon.pas' rev: 21.00

#ifndef SbpkicommonHPP
#define SbpkicommonHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbpkcs7utils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpkicommon
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBCMSSignatureValidity { csvValid, csvInvalid, csvSignerNotFound, csvGeneralFailure };
#pragma option pop

#pragma option push -b-
enum TSBCMSValidationOption { cvoRecursiveValidation, cvoValidateChains, cvoValidateTimes, cvoCheckRevocationStatus, cvoRequireTimestamps, cvoIgnoreLocalTimestamps, cvoValidateTrusts };
#pragma option pop

typedef Set<TSBCMSValidationOption, cvoRecursiveValidation, cvoValidateTrusts>  TSBCMSValidationOptions;

#pragma option push -b-
enum TSBCMSAdvancedSignatureValidity { casvValid, casvSignatureCorrupted, casvSignerNotFound, casvIncompleteChain, casvBadCountersignature, casvBadTimestamp, casvCertificateExpired, casvCertificateRevoked, casvCertificateCorrupted, casvUntrustedCA, casvRevInfoNotFound, casvTimestampInfoNotFound, casvFailure, casvCertificateMalformed, casvUnknown, casvChainValidationFailed };
#pragma option pop

#pragma option push -b-
enum TSBPKIStatus { psGranted, psGrantedWithMods, psRejection, psWaiting, psRevocationWarning, psRevocationNotification, psKeyUpdateWarning };
#pragma option pop

#pragma option push -b-
enum TSBPKIFailureInfo { pfiBadAlg, pfiBadMessageCheck, pfiBadRequest, pfiBadTime, pfiBadCertId, pfiBadDataFormat, pfiWrongAuthority, pfiIncorrectData, pfiMissingTimeStamp, pfiBadPOP };
#pragma option pop

//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbpkicommon */
using namespace Sbpkicommon;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbpkicommonHPP
