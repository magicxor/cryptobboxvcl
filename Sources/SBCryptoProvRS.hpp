// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovrs.pas' rev: 21.00

#ifndef SbcryptoprovrsHPP
#define SbcryptoprovrsHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovrs
{
//-- type declarations -------------------------------------------------------
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE System::ResourceString _SInvalidPublicKey;
#define Sbcryptoprovrs_SInvalidPublicKey System::LoadResourceString(&Sbcryptoprovrs::_SInvalidPublicKey)
extern PACKAGE System::ResourceString _SInvalidSecretKey;
#define Sbcryptoprovrs_SInvalidSecretKey System::LoadResourceString(&Sbcryptoprovrs::_SInvalidSecretKey)
extern PACKAGE System::ResourceString _SBufferTooSmall;
#define Sbcryptoprovrs_SBufferTooSmall System::LoadResourceString(&Sbcryptoprovrs::_SBufferTooSmall)
extern PACKAGE System::ResourceString _SUnsupportedAlgorithmInt;
#define Sbcryptoprovrs_SUnsupportedAlgorithmInt System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedAlgorithmInt)
extern PACKAGE System::ResourceString _SUnsupportedAlgorithmStr;
#define Sbcryptoprovrs_SUnsupportedAlgorithmStr System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedAlgorithmStr)
extern PACKAGE System::ResourceString _SUnsupportedPropertyStr;
#define Sbcryptoprovrs_SUnsupportedPropertyStr System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedPropertyStr)
extern PACKAGE System::ResourceString _SUnknownAlgorithmProperty;
#define Sbcryptoprovrs_SUnknownAlgorithmProperty System::LoadResourceString(&Sbcryptoprovrs::_SUnknownAlgorithmProperty)
extern PACKAGE System::ResourceString _SCryptoAPIError;
#define Sbcryptoprovrs_SCryptoAPIError System::LoadResourceString(&Sbcryptoprovrs::_SCryptoAPIError)
extern PACKAGE System::ResourceString _SUnsupportedHashAlgorithmInt;
#define Sbcryptoprovrs_SUnsupportedHashAlgorithmInt System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedHashAlgorithmInt)
extern PACKAGE System::ResourceString _SUnsupportedPropertyValue;
#define Sbcryptoprovrs_SUnsupportedPropertyValue System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedPropertyValue)
extern PACKAGE System::ResourceString _SModuleInitializationFailed;
#define Sbcryptoprovrs_SModuleInitializationFailed System::LoadResourceString(&Sbcryptoprovrs::_SModuleInitializationFailed)
extern PACKAGE System::ResourceString _SHashAlgorithmMismatch;
#define Sbcryptoprovrs_SHashAlgorithmMismatch System::LoadResourceString(&Sbcryptoprovrs::_SHashAlgorithmMismatch)
extern PACKAGE System::ResourceString _SInvalidContext;
#define Sbcryptoprovrs_SInvalidContext System::LoadResourceString(&Sbcryptoprovrs::_SInvalidContext)
extern PACKAGE System::ResourceString _SInvalidAlgorithm;
#define Sbcryptoprovrs_SInvalidAlgorithm System::LoadResourceString(&Sbcryptoprovrs::_SInvalidAlgorithm)
extern PACKAGE System::ResourceString _SCannotChangeAlgorithm;
#define Sbcryptoprovrs_SCannotChangeAlgorithm System::LoadResourceString(&Sbcryptoprovrs::_SCannotChangeAlgorithm)
extern PACKAGE System::ResourceString _SCannotChangeROProperty;
#define Sbcryptoprovrs_SCannotChangeROProperty System::LoadResourceString(&Sbcryptoprovrs::_SCannotChangeROProperty)
extern PACKAGE System::ResourceString _SNotASymmetricCipherContext;
#define Sbcryptoprovrs_SNotASymmetricCipherContext System::LoadResourceString(&Sbcryptoprovrs::_SNotASymmetricCipherContext)
extern PACKAGE System::ResourceString _SNotAHashContext;
#define Sbcryptoprovrs_SNotAHashContext System::LoadResourceString(&Sbcryptoprovrs::_SNotAHashContext)
extern PACKAGE System::ResourceString _SNotAPKIContext;
#define Sbcryptoprovrs_SNotAPKIContext System::LoadResourceString(&Sbcryptoprovrs::_SNotAPKIContext)
extern PACKAGE System::ResourceString _SNotARC4Context;
#define Sbcryptoprovrs_SNotARC4Context System::LoadResourceString(&Sbcryptoprovrs::_SNotARC4Context)
extern PACKAGE System::ResourceString _SNotAGOST89Context;
#define Sbcryptoprovrs_SNotAGOST89Context System::LoadResourceString(&Sbcryptoprovrs::_SNotAGOST89Context)
extern PACKAGE System::ResourceString _SNotAGOST2001Context;
#define Sbcryptoprovrs_SNotAGOST2001Context System::LoadResourceString(&Sbcryptoprovrs::_SNotAGOST2001Context)
extern PACKAGE System::ResourceString _SNotARSAContext;
#define Sbcryptoprovrs_SNotARSAContext System::LoadResourceString(&Sbcryptoprovrs::_SNotARSAContext)
extern PACKAGE System::ResourceString _SNotAECDSAContext;
#define Sbcryptoprovrs_SNotAECDSAContext System::LoadResourceString(&Sbcryptoprovrs::_SNotAECDSAContext)
extern PACKAGE System::ResourceString _SCannotCloneContext;
#define Sbcryptoprovrs_SCannotCloneContext System::LoadResourceString(&Sbcryptoprovrs::_SCannotCloneContext)
extern PACKAGE System::ResourceString _SInternalError;
#define Sbcryptoprovrs_SInternalError System::LoadResourceString(&Sbcryptoprovrs::_SInternalError)
extern PACKAGE System::ResourceString _SUnsupportedOperation;
#define Sbcryptoprovrs_SUnsupportedOperation System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedOperation)
extern PACKAGE System::ResourceString _SInternalException;
#define Sbcryptoprovrs_SInternalException System::LoadResourceString(&Sbcryptoprovrs::_SInternalException)
extern PACKAGE System::ResourceString _SInvalidKeyMaterial;
#define Sbcryptoprovrs_SInvalidKeyMaterial System::LoadResourceString(&Sbcryptoprovrs::_SInvalidKeyMaterial)
extern PACKAGE System::ResourceString _SNoIVInKeyMaterial;
#define Sbcryptoprovrs_SNoIVInKeyMaterial System::LoadResourceString(&Sbcryptoprovrs::_SNoIVInKeyMaterial)
extern PACKAGE System::ResourceString _SInvalidKeyFormat;
#define Sbcryptoprovrs_SInvalidKeyFormat System::LoadResourceString(&Sbcryptoprovrs::_SInvalidKeyFormat)
extern PACKAGE System::ResourceString _SInvalidCipherMode;
#define Sbcryptoprovrs_SInvalidCipherMode System::LoadResourceString(&Sbcryptoprovrs::_SInvalidCipherMode)
extern PACKAGE System::ResourceString _SInvalidCryptoProvider;
#define Sbcryptoprovrs_SInvalidCryptoProvider System::LoadResourceString(&Sbcryptoprovrs::_SInvalidCryptoProvider)
extern PACKAGE System::ResourceString _SCannotCompleteOperation;
#define Sbcryptoprovrs_SCannotCompleteOperation System::LoadResourceString(&Sbcryptoprovrs::_SCannotCompleteOperation)
extern PACKAGE System::ResourceString _SInterruptedByUser;
#define Sbcryptoprovrs_SInterruptedByUser System::LoadResourceString(&Sbcryptoprovrs::_SInterruptedByUser)
extern PACKAGE System::ResourceString _SUnsupportedCryptoProvider;
#define Sbcryptoprovrs_SUnsupportedCryptoProvider System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedCryptoProvider)
extern PACKAGE System::ResourceString _SPublicKeyNotFound;
#define Sbcryptoprovrs_SPublicKeyNotFound System::LoadResourceString(&Sbcryptoprovrs::_SPublicKeyNotFound)
extern PACKAGE System::ResourceString _SSecretKeyNotFound;
#define Sbcryptoprovrs_SSecretKeyNotFound System::LoadResourceString(&Sbcryptoprovrs::_SSecretKeyNotFound)
extern PACKAGE System::ResourceString _SBadKeyMaterial;
#define Sbcryptoprovrs_SBadKeyMaterial System::LoadResourceString(&Sbcryptoprovrs::_SBadKeyMaterial)
extern PACKAGE System::ResourceString _SInvalidKeyMaterialType;
#define Sbcryptoprovrs_SInvalidKeyMaterialType System::LoadResourceString(&Sbcryptoprovrs::_SInvalidKeyMaterialType)
extern PACKAGE System::ResourceString _SSigningFailed;
#define Sbcryptoprovrs_SSigningFailed System::LoadResourceString(&Sbcryptoprovrs::_SSigningFailed)
extern PACKAGE System::ResourceString _SEncryptionFailed;
#define Sbcryptoprovrs_SEncryptionFailed System::LoadResourceString(&Sbcryptoprovrs::_SEncryptionFailed)
extern PACKAGE System::ResourceString _SDecryptionFailed;
#define Sbcryptoprovrs_SDecryptionFailed System::LoadResourceString(&Sbcryptoprovrs::_SDecryptionFailed)
extern PACKAGE System::ResourceString _SKEKDerivationFailed;
#define Sbcryptoprovrs_SKEKDerivationFailed System::LoadResourceString(&Sbcryptoprovrs::_SKEKDerivationFailed)
extern PACKAGE System::ResourceString _SUnsupportedEncryptionType;
#define Sbcryptoprovrs_SUnsupportedEncryptionType System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedEncryptionType)
extern PACKAGE System::ResourceString _SOnlyDetachedSigningSupported;
#define Sbcryptoprovrs_SOnlyDetachedSigningSupported System::LoadResourceString(&Sbcryptoprovrs::_SOnlyDetachedSigningSupported)
extern PACKAGE System::ResourceString _SInputTooLong;
#define Sbcryptoprovrs_SInputTooLong System::LoadResourceString(&Sbcryptoprovrs::_SInputTooLong)
extern PACKAGE System::ResourceString _SBadSignatureFormatting;
#define Sbcryptoprovrs_SBadSignatureFormatting System::LoadResourceString(&Sbcryptoprovrs::_SBadSignatureFormatting)
extern PACKAGE System::ResourceString _SInvalidSignature;
#define Sbcryptoprovrs_SInvalidSignature System::LoadResourceString(&Sbcryptoprovrs::_SInvalidSignature)
extern PACKAGE System::ResourceString _SCannotModifyReadOnlyProperty;
#define Sbcryptoprovrs_SCannotModifyReadOnlyProperty System::LoadResourceString(&Sbcryptoprovrs::_SCannotModifyReadOnlyProperty)
extern PACKAGE System::ResourceString _SKeyGenerationFailed;
#define Sbcryptoprovrs_SKeyGenerationFailed System::LoadResourceString(&Sbcryptoprovrs::_SKeyGenerationFailed)
extern PACKAGE System::ResourceString _SNotASigningAlgorithm;
#define Sbcryptoprovrs_SNotASigningAlgorithm System::LoadResourceString(&Sbcryptoprovrs::_SNotASigningAlgorithm)
extern PACKAGE System::ResourceString _SFeatureNotAvailable;
#define Sbcryptoprovrs_SFeatureNotAvailable System::LoadResourceString(&Sbcryptoprovrs::_SFeatureNotAvailable)
extern PACKAGE System::ResourceString _SFailedToModifyReadonlyProperty;
#define Sbcryptoprovrs_SFailedToModifyReadonlyProperty System::LoadResourceString(&Sbcryptoprovrs::_SFailedToModifyReadonlyProperty)
extern PACKAGE System::ResourceString _SUnsupportedKeyMaterial;
#define Sbcryptoprovrs_SUnsupportedKeyMaterial System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedKeyMaterial)
extern PACKAGE System::ResourceString _SKeyPropertyNotSupported;
#define Sbcryptoprovrs_SKeyPropertyNotSupported System::LoadResourceString(&Sbcryptoprovrs::_SKeyPropertyNotSupported)
extern PACKAGE System::ResourceString _SInvalidPadding;
#define Sbcryptoprovrs_SInvalidPadding System::LoadResourceString(&Sbcryptoprovrs::_SInvalidPadding)
extern PACKAGE System::ResourceString _SKeyDecryptionFailed;
#define Sbcryptoprovrs_SKeyDecryptionFailed System::LoadResourceString(&Sbcryptoprovrs::_SKeyDecryptionFailed)
extern PACKAGE System::ResourceString _SDriverNotFound;
#define Sbcryptoprovrs_SDriverNotFound System::LoadResourceString(&Sbcryptoprovrs::_SDriverNotFound)
extern PACKAGE System::ResourceString _SUnsupportedFeature;
#define Sbcryptoprovrs_SUnsupportedFeature System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedFeature)
extern PACKAGE System::ResourceString _SCannotClonePKCS11Context;
#define Sbcryptoprovrs_SCannotClonePKCS11Context System::LoadResourceString(&Sbcryptoprovrs::_SCannotClonePKCS11Context)
extern PACKAGE System::ResourceString _SCannotCloneWin32Context;
#define Sbcryptoprovrs_SCannotCloneWin32Context System::LoadResourceString(&Sbcryptoprovrs::_SCannotCloneWin32Context)
extern PACKAGE System::ResourceString _SKeyAlreadyPrepared;
#define Sbcryptoprovrs_SKeyAlreadyPrepared System::LoadResourceString(&Sbcryptoprovrs::_SKeyAlreadyPrepared)
extern PACKAGE System::ResourceString _SFailedToExportSecretKey;
#define Sbcryptoprovrs_SFailedToExportSecretKey System::LoadResourceString(&Sbcryptoprovrs::_SFailedToExportSecretKey)
extern PACKAGE System::ResourceString _SObjectNotFound;
#define Sbcryptoprovrs_SObjectNotFound System::LoadResourceString(&Sbcryptoprovrs::_SObjectNotFound)
extern PACKAGE System::ResourceString _SBadObjectType;
#define Sbcryptoprovrs_SBadObjectType System::LoadResourceString(&Sbcryptoprovrs::_SBadObjectType)
extern PACKAGE System::ResourceString _SHandleNotFound;
#define Sbcryptoprovrs_SHandleNotFound System::LoadResourceString(&Sbcryptoprovrs::_SHandleNotFound)
extern PACKAGE System::ResourceString _SMethodNotImplemented;
#define Sbcryptoprovrs_SMethodNotImplemented System::LoadResourceString(&Sbcryptoprovrs::_SMethodNotImplemented)
extern PACKAGE System::ResourceString _SPublicKeyTooLong;
#define Sbcryptoprovrs_SPublicKeyTooLong System::LoadResourceString(&Sbcryptoprovrs::_SPublicKeyTooLong)
extern PACKAGE System::ResourceString _SInvalidECDomainParameters;
#define Sbcryptoprovrs_SInvalidECDomainParameters System::LoadResourceString(&Sbcryptoprovrs::_SInvalidECDomainParameters)
extern PACKAGE System::ResourceString _SUnknownEC;
#define Sbcryptoprovrs_SUnknownEC System::LoadResourceString(&Sbcryptoprovrs::_SUnknownEC)
extern PACKAGE System::ResourceString _SUnknownField;
#define Sbcryptoprovrs_SUnknownField System::LoadResourceString(&Sbcryptoprovrs::_SUnknownField)
extern PACKAGE System::ResourceString _SInvalidKeyProperty;
#define Sbcryptoprovrs_SInvalidKeyProperty System::LoadResourceString(&Sbcryptoprovrs::_SInvalidKeyProperty)
extern PACKAGE System::ResourceString _SOperationInitializationFailed;
#define Sbcryptoprovrs_SOperationInitializationFailed System::LoadResourceString(&Sbcryptoprovrs::_SOperationInitializationFailed)
extern PACKAGE System::ResourceString _SInstantiationFailed;
#define Sbcryptoprovrs_SInstantiationFailed System::LoadResourceString(&Sbcryptoprovrs::_SInstantiationFailed)
extern PACKAGE System::ResourceString _SInvalidPropertyValue;
#define Sbcryptoprovrs_SInvalidPropertyValue System::LoadResourceString(&Sbcryptoprovrs::_SInvalidPropertyValue)
extern PACKAGE System::ResourceString _SUnsupportedPublicKeyFormat;
#define Sbcryptoprovrs_SUnsupportedPublicKeyFormat System::LoadResourceString(&Sbcryptoprovrs::_SUnsupportedPublicKeyFormat)
extern PACKAGE System::ResourceString _SCannotUnregisterDefaultProvider;
#define Sbcryptoprovrs_SCannotUnregisterDefaultProvider System::LoadResourceString(&Sbcryptoprovrs::_SCannotUnregisterDefaultProvider)
extern PACKAGE System::ResourceString _SNoSuitableProviderInt;
#define Sbcryptoprovrs_SNoSuitableProviderInt System::LoadResourceString(&Sbcryptoprovrs::_SNoSuitableProviderInt)
extern PACKAGE System::ResourceString _SNoSuitableProviderStr;
#define Sbcryptoprovrs_SNoSuitableProviderStr System::LoadResourceString(&Sbcryptoprovrs::_SNoSuitableProviderStr)

}	/* namespace Sbcryptoprovrs */
using namespace Sbcryptoprovrs;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovrsHPP
