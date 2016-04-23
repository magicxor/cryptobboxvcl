(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProvRS;

interface

resourcestring
  SInvalidPublicKey = 'Invalid public key';
  SInvalidSecretKey = 'Invalid secret key';
  SBufferTooSmall = 'Buffer too small';
  SUnsupportedAlgorithmInt = 'Unsupported algorithm (%d)';
  SUnsupportedAlgorithmStr = 'Unsupported algorithm (%s)';
  SUnsupportedPropertyStr = 'Unsupported property (%s)';
  SUnknownAlgorithmProperty = 'Unknown algorithm property (%s)';
  SCryptoAPIError = 'CryptoAPI error %d';
  SUnsupportedHashAlgorithmInt = 'Unsupported hash algorithm (%d)';
  SUnsupportedPropertyValue = 'Unsupported property value (%s)';
  SModuleInitializationFailed = 'Module initialization failed (%s)';
  SHashAlgorithmMismatch = 'Hash algorithm mismatch (%d)';
  SInvalidContext = 'Invalid context';
  SInvalidAlgorithm = 'Invalid algorithm';
  SCannotChangeAlgorithm = 'The algorithm cannot be changed';
  SCannotChangeROProperty = 'Cannot change read-only property';
  SNotASymmetricCipherContext = 'Not a symmetric cipher context';
  SNotAHashContext = 'Not a hash context';
  SNotAPKIContext = 'Not a public key operation context';
  SNotARC4Context = 'Not a RC4 context';
  SNotAGOST89Context = 'Not a GOST 28147-89 context';
  SNotAGOST2001Context = 'Not a GOST 34.10-2001 context';
  SNotARSAContext = 'Not a RSA context';
  SNotAECDSAContext = 'Not a ECDSA context';
  SCannotCloneContext = 'Cannot clone a context';
  SInternalError = 'Internal error';
  SUnsupportedOperation = 'Unsupported operation';
  SInternalException = 'Internal exception';
  SInvalidKeyMaterial = 'Invalid key material';
  SNoIVInKeyMaterial = 'Required IV not set in key material';
  SInvalidKeyFormat = 'Invalid key format';
  SInvalidCipherMode = 'Invalid cipher mode of operation';
  SInvalidCryptoProvider = 'Invalid cryptographic provider';
  SCannotCompleteOperation = 'Cannot complete operation';
  SInterruptedByUser = 'Interrupted by user';
  SUnsupportedCryptoProvider = 'Unsupported crypto provider';
  SPublicKeyNotFound = 'Public key not found';
  SSecretKeyNotFound = 'Secret key not found';
  SBadKeyMaterial = 'Bad key material';
  SInvalidKeyMaterialType = 'Invalid key material type';
  SSigningFailed = 'Signing failed';
  SEncryptionFailed = 'Encryption failed';
  SDecryptionFailed = 'Decryption failed';
  SKEKDerivationFailed = 'KEK derivation failed';
  SUnsupportedEncryptionType = 'Encryption type';
  SOnlyDetachedSigningSupported = 'Only detached signing supported';
  SInputTooLong = 'Input too long';
  SBadSignatureFormatting = 'Bad signature formatting';
  SInvalidSignature = 'Invalid signature';
  SCannotModifyReadOnlyProperty = 'Cannot modify read-only property';
  SKeyGenerationFailed = 'Key generation failed';
  SNotASigningAlgorithm = 'Not a signing algorithm';
  SFeatureNotAvailable = 'Feature not available';
  SFailedToModifyReadonlyProperty = 'Failed to modify read-only property';
  SUnsupportedKeyMaterial = 'Unsupported key material';
  SKeyPropertyNotSupported = 'Key does not support the property';
  SInvalidPadding = 'Invalid symmetric cipher padding';
  SKeyDecryptionFailed = 'Key decryption failed';
  SDriverNotFound = 'Driver not found';
  SUnsupportedFeature = 'Unsupported feature';
  SCannotClonePKCS11Context = 'Cannot clone PKCS#11 context';
  SCannotCloneWin32Context = 'Cannot clone Win32 context';
  SKeyAlreadyPrepared = 'Key is already prepared';
  SFailedToExportSecretKey = 'Failed to export secret key';
  SObjectNotFound = 'Object not found';
  SBadObjectType = 'Bad object type';
  SHandleNotFound = 'Handle not found';
  SMethodNotImplemented = 'Method not implemented';
  SPublicKeyTooLong = 'Public key is too long';
  SInvalidECDomainParameters = 'Invalid elliptic curve domain parameters';
  SUnknownEC = 'Unknown elliptic curve';
  SUnknownField = 'Unknown elliptic curve field';
  SInvalidKeyProperty = 'Invalid key property';
  SOperationInitializationFailed = 'Operation initialization failed';
  SInstantiationFailed = 'Failed to instantiate the type';
  SInvalidPropertyValue = 'Invalid property value';
  SUnsupportedPublicKeyFormat = 'Unsupported public key format';
  SCannotUnregisterDefaultProvider = 'Cannot unregister the default cryptographic provider';
  SNoSuitableProviderInt = 'Unsupported cryptographic operation. Operation: %d, Algorithm: %d, Mode: %d.';
  SNoSuitableProviderStr = 'Unsupported cryptographic operation. Operation: %d, Algorithm: %s, Params: %s, Mode: %d.';

implementation

end.
