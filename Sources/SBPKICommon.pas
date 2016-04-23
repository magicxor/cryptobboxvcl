(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBPKICommon;

interface

uses
  SBX509, SBPKCS7Utils;



type
  TSBCMSSignatureValidity = (csvValid, csvInvalid, csvSignerNotFound, csvGeneralFailure);

  TSBCMSValidationOption = (cvoRecursiveValidation, cvoValidateChains,
    cvoValidateTimes, cvoCheckRevocationStatus, cvoRequireTimestamps,
    cvoIgnoreLocalTimestamps, cvoValidateTrusts);
  TSBCMSValidationOptions = set of TSBCMSValidationOption;

  // add casvCheckCertPurposes
  TSBCMSAdvancedSignatureValidity = (casvValid, casvSignatureCorrupted,
    casvSignerNotFound, casvIncompleteChain, casvBadCountersignature, casvBadTimestamp,
    casvCertificateExpired, casvCertificateRevoked, casvCertificateCorrupted,
    casvUntrustedCA, casvRevInfoNotFound, casvTimestampInfoNotFound, casvFailure,
    casvCertificateMalformed, casvUnknown, casvChainValidationFailed); 


type
  TSBPKIStatus = (psGranted, psGrantedWithMods, psRejection, psWaiting,
    psRevocationWarning, psRevocationNotification, psKeyUpdateWarning);

  TSBPKIFailureInfo = (pfiBadAlg, pfiBadMessageCheck, pfiBadRequest,
    pfiBadTime, pfiBadCertId, pfiBadDataFormat, pfiWrongAuthority,
    pfiIncorrectData, pfiMissingTimeStamp, pfiBadPOP);

implementation

end.
