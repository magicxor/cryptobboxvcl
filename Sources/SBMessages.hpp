// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbmessages.pas' rev: 21.00

#ifndef SbmessagesHPP
#define SbmessagesHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbzlib.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit
#include <Sbcrlstorage.hpp>	// Pascal unit
#include <Sbpkcs7.hpp>	// Pascal unit
#include <Sbpkcs7utils.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbalgorithmidentifier.hpp>	// Pascal unit
#include <Sbcustomcrypto.hpp>	// Pascal unit
#include <Sbsymmetriccrypto.hpp>	// Pascal unit
#include <Sbpublickeycrypto.hpp>	// Pascal unit
#include <Sbeccommon.hpp>	// Pascal unit
#include <Sbgost2814789.hpp>	// Pascal unit
#include <Sbgost341001.hpp>	// Pascal unit
#include <Sbtspclient.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbstreams.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbmessages
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElMessageProcessor;
class PASCALIMPLEMENTATION TElMessageProcessor : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	Sbutils::TSBProgressEvent FOnProgress;
	System::UnicodeString FErrorInfo;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	bool FAlignEncryptedKey;
	Sbtypes::ByteArray FGOSTParamSet;
	void __fastcall SetGOSTParamSet(const Sbtypes::ByteArray V);
	bool __fastcall DoProgress(__int64 Total, __int64 Current);
	void __fastcall RaiseCancelledByUserError(void);
	bool FUseOAEP;
	Sbtypes::ByteArray __fastcall AlignEncrypted(const Sbtypes::ByteArray EK, Sbx509::TElX509Certificate* Certificate);
	bool __fastcall EncryptRSA(const Sbtypes::ByteArray Key, Sbx509::TElX509Certificate* Certificate, Sbtypes::ByteArray &EncryptedKey)/* overload */;
	bool __fastcall EncryptRSAOAEP(const Sbtypes::ByteArray Key, Sbx509::TElX509Certificate* Certificate, Sbtypes::ByteArray &EncryptedKey)/* overload */;
	bool __fastcall EncryptGOST2001(const Sbtypes::ByteArray Key, Sbx509::TElX509Certificate* Certificate, Sbtypes::ByteArray &EncryptedKey)/* overload */;
	bool __fastcall SignRSA(Sbx509::TElX509Certificate* Certificate, void * Digest, int DigestSize, const Sbtypes::ByteArray OID, Sbtypes::ByteArray &EncryptedDigest)/* overload */;
	bool __fastcall DecryptRSA(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Recipient* Recipient, Sbtypes::ByteArray &Key)/* overload */;
	bool __fastcall DecryptRSAOAEP(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Recipient* Recipient, Sbtypes::ByteArray &Key)/* overload */;
	bool __fastcall DecryptRSAForSigner(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Signer* Signer, Sbtypes::ByteArray &Digest)/* overload */;
	bool __fastcall DecryptGOST2001(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Recipient* Recipient, Sbtypes::ByteArray &Key)/* overload */;
	bool __fastcall VerifyDSA(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Signer* Signer, void * Digest, int Size);
	bool __fastcall VerifyECDSA(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Signer* Signer, void * Digest, int Size);
	bool __fastcall VerifyGOST2001(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Signer* Signer, void * Digest, int Size);
	bool __fastcall VerifyRSAPSS(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Signer* Signer, void * Digest, int Size, int HashAlgorithm, int SaltSize);
	bool __fastcall EncryptKey(const Sbtypes::ByteArray Key, Sbx509::TElX509Certificate* Certificate, Sbtypes::ByteArray &EncryptedKey);
	bool __fastcall DecryptKey(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Recipient* Recipient, Sbtypes::ByteArray &Key);
	bool __fastcall ImportEncryptedSymmetricKey(Sbx509::TElX509Certificate* Certificate, Sbpkcs7::TElPKCS7Recipient* Recipient, Sbpkcs7::TElPKCS7Message* Msg, Sbsymmetriccrypto::TElSymmetricKeyMaterial* &Key);
	bool __fastcall FillRecipient(Sbpkcs7::TElPKCS7Recipient* Recipient, Sbx509::TElX509Certificate* Certificate, const Sbtypes::ByteArray Key);
	bool __fastcall CalculateMAC(void * Buffer, int Size, const Sbtypes::ByteArray Key, Sbtypes::ByteArray &Mac, int MacAlg, System::TObject* PKCS7Data = (System::TObject*)(0x0), Sbasn1tree::TElASN1DataSource* DataSource = (Sbasn1tree::TElASN1DataSource*)(0x0), bool FireOnProgress = false);
	void __fastcall CalculateDigests(void * Buffer, int Size, Classes::TList* HashFunctions, Sbutils::TElByteArrayList* Digests, System::TObject* PKCS7Data = (System::TObject*)(0x0), Sbasn1tree::TElASN1DataSource* DataSource = (Sbasn1tree::TElASN1DataSource*)(0x0), bool FireOnProgress = false);
	Sbtypes::ByteArray __fastcall CalculateDigest(void * Buffer, int Size, int Alg, System::TObject* PKCS7Data = (System::TObject*)(0x0), Sbasn1tree::TElASN1DataSource* DataSource = (Sbasn1tree::TElASN1DataSource*)(0x0), bool FireOnProgress = false);
	void __fastcall HandleProgress(System::TObject* Sender, __int64 Total, __int64 Current, bool &Cancel);
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	void __fastcall SetCryptoProviderManager(Sbcryptoprov::TElCustomCryptoProviderManager* Value);
	
public:
	__property System::UnicodeString ErrorInfo = {read=FErrorInfo};
	
__published:
	__property Sbcryptoprov::TElCustomCryptoProviderManager* CryptoProviderManager = {read=FCryptoProviderManager, write=SetCryptoProviderManager};
	__property bool AlignEncryptedKey = {read=FAlignEncryptedKey, write=FAlignEncryptedKey, default=0};
	__property Sbutils::TSBProgressEvent OnProgress = {read=FOnProgress, write=FOnProgress};
public:
	/* TComponent.Create */ inline __fastcall virtual TElMessageProcessor(Classes::TComponent* AOwner) : Classes::TComponent(AOwner) { }
	/* TComponent.Destroy */ inline __fastcall virtual ~TElMessageProcessor(void) { }
	
};

typedef TElMessageProcessor ElMessageProcessor
#pragma option push -b-
enum TSBEncryptionOption { eoIgnoreSupportedWin32Algorithms, eoNoOuterContentInfo };
#pragma option pop

typedef Set<TSBEncryptionOption, eoIgnoreSupportedWin32Algorithms, eoNoOuterContentInfo>  TSBEncryptionOptions;

class DELPHICLASS TElMessageEncryptor;
class PASCALIMPLEMENTATION TElMessageEncryptor : public TElMessageProcessor
{
	typedef TElMessageProcessor inherited;
	
private:
	Sbcustomcertstorage::TElCustomCertStorage* FCertStorage;
	int FAlgorithm;
	int FBitsInKey;
	Sbrandom::TElRandom* FRandom;
	bool FUseUndefSize;
	bool FUseImplicitContentEncoding;
	TSBEncryptionOptions FEncryptionOptions;
	Sbcustomcertstorage::TElCustomCertStorage* FOriginatorCertificates;
	Sbcrlstorage::TElCustomCRLStorage* FOriginatorCRLs;
	Sbpkcs7utils::TElPKCS7Attributes* FUnprotectedAttributes;
	
protected:
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	void __fastcall GenerateContentKey(void * KeyBuffer, int KeySize, void * IVBuffer, int IVSize);
	bool __fastcall EncryptContent(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const Sbtypes::ByteArray Key, const Sbtypes::ByteArray IV);
	Sbtypes::ByteArray __fastcall FillRC2Params(int KeyLen, const Sbtypes::ByteArray IV);
	int __fastcall GetAppropriateEnvDataVersion(void);
	int __fastcall ChooseEncryptionAlgorithm(Sbtypes::TSBArrayOfPairs const *Algs, const int Algs_Size, int &Bits);
	bool __fastcall AdjustKeyAndIVLengths(Sbtypes::ByteArray &Key, Sbtypes::ByteArray &IV);
	int __fastcall CalculateEstimatedSize(int InSize);
	void __fastcall SetupAlgorithmParams(Sbpkcs7::TElPKCS7EnvelopedData* EnvData, const Sbtypes::ByteArray Key, const Sbtypes::ByteArray IV);
	Classes::TStream* __fastcall CreateEncryptingStream(Classes::TStream* Source, __int64 SourceCount, const Sbtypes::ByteArray Key, const Sbtypes::ByteArray IV);
	void __fastcall OnEncStreamProgress(System::TObject* Sender, __int64 Total, __int64 Current, bool &Cancel);
	void __fastcall SetCertStorage(Sbcustomcertstorage::TElCustomCertStorage* Value);
	void __fastcall SetOriginatorCertificates(Sbcustomcertstorage::TElCustomCertStorage* Value);
	void __fastcall SetOriginatorCRLs(Sbcrlstorage::TElCustomCRLStorage* Value);
	
public:
	__fastcall virtual TElMessageEncryptor(Classes::TComponent* AOwner);
	__fastcall virtual ~TElMessageEncryptor(void);
	int __fastcall Encrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	int __fastcall Encrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, void * Key, int KeySize)/* overload */;
	int __fastcall Encrypt(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000)/* overload */;
	int __fastcall Encrypt(Classes::TStream* InStream, Classes::TStream* OutStream, void * Key, int KeySize, __int64 InCount = 0x000000000)/* overload */;
	__property Sbtypes::ByteArray GOSTParamSet = {read=FGOSTParamSet, write=SetGOSTParamSet};
	
__published:
	__property Sbcustomcertstorage::TElCustomCertStorage* CertStorage = {read=FCertStorage, write=SetCertStorage};
	__property int Algorithm = {read=FAlgorithm, write=FAlgorithm, nodefault};
	__property int BitsInKey = {read=FBitsInKey, write=FBitsInKey, nodefault};
	__property bool UseUndefSize = {read=FUseUndefSize, write=FUseUndefSize, default=1};
	__property bool UseOAEP = {read=FUseOAEP, write=FUseOAEP, nodefault};
	__property TSBEncryptionOptions EncryptionOptions = {read=FEncryptionOptions, write=FEncryptionOptions, nodefault};
	__property bool UseImplicitContentEncoding = {read=FUseImplicitContentEncoding, write=FUseImplicitContentEncoding, nodefault};
	__property Sbcustomcertstorage::TElCustomCertStorage* OriginatorCertificates = {read=FOriginatorCertificates, write=SetOriginatorCertificates};
	__property Sbcrlstorage::TElCustomCRLStorage* OriginatorCRLs = {read=FOriginatorCRLs, write=SetOriginatorCRLs};
	__property Sbpkcs7utils::TElPKCS7Attributes* UnprotectedAttributes = {read=FUnprotectedAttributes};
};

typedef TElMessageEncryptor ElMessageEncryptor
typedef void __fastcall (__closure *TSBCertIDsEvent)(System::TObject* Sender, Classes::TList* CertIDs);

#pragma option push -b-
enum TSBDecryptionOption { doNoOuterContentInfo };
#pragma option pop

typedef Set<TSBDecryptionOption, doNoOuterContentInfo, doNoOuterContentInfo>  TSBDecryptionOptions;

class DELPHICLASS TElMessageDecryptor;
class PASCALIMPLEMENTATION TElMessageDecryptor : public TElMessageProcessor
{
	typedef TElMessageProcessor inherited;
	
private:
	Sbcustomcertstorage::TElCustomCertStorage* FCertStorage;
	int FAlgorithm;
	int FBitsInKey;
	int FUsedCertificate;
	Classes::TList* FCertIDs;
	TSBCertIDsEvent FOnCertIDs;
	TSBDecryptionOptions FDecryptionOptions;
	Sbcustomcertstorage::TElMemoryCertStorage* FOriginatorCertificates;
	Sbcrlstorage::TElMemoryCRLStorage* FOriginatorCRLs;
	Sbpkcs7utils::TElPKCS7Attributes* FUnprotectedAttributes;
	
protected:
	bool __fastcall DecryptContent(Sbpkcs7::TElPKCS7EncryptedContent* Content, const Sbtypes::ByteArray Key, Sbsymmetriccrypto::TElSymmetricKeyMaterial* KeyMaterial, void * OutBuffer, int &OutSize, Classes::TStream* OutStream = (Classes::TStream*)(0x0));
	unsigned __fastcall GetRC2KeyLengthByIdentifier(const Sbtypes::ByteArray Id);
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	void __fastcall ClearCertIDs(void);
	Sbx509::TElX509Certificate* __fastcall FindRecipientCertificate(Sbpkcs7::TElPKCS7Message* Msg, Sbpkcs7::TElPKCS7Recipient* &Recipient, int &CertIndex);
	void __fastcall ExtractRecipientIDs(Sbpkcs7::TElPKCS7Message* Msg);
	void __fastcall ExtractOtherInfo(Sbpkcs7::TElPKCS7Message* Msg);
	void __fastcall DecryptProgressFunc(System::TObject* Sender, __int64 Total, __int64 Current, bool &Cancel);
	bool __fastcall ExtractRC2KeyParameters(Sbpkcs7::TElPKCS7EncryptedContent* Content, const Sbtypes::ByteArray Key, Sbtypes::ByteArray &IV);
	bool __fastcall ExtractGOSTKeyParameters(Sbpkcs7::TElPKCS7EncryptedContent* Content, Sbtypes::ByteArray &ParamSet, Sbtypes::ByteArray &IV);
	void __fastcall SetCertStorage(Sbcustomcertstorage::TElCustomCertStorage* Value);
	int __fastcall GetCertIDCount(void);
	int __fastcall GetUsedCertificate(void);
	Sbpkcs7utils::TElPKCS7Issuer* __fastcall GetCertIDs(int Index);
	
public:
	__fastcall virtual TElMessageDecryptor(Classes::TComponent* AOwner);
	__fastcall virtual ~TElMessageDecryptor(void);
	int __fastcall Decrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	int __fastcall Decrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, void * Key, int KeySize)/* overload */;
	int __fastcall Decrypt(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000)/* overload */;
	int __fastcall Decrypt(Classes::TStream* InStream, Classes::TStream* OutStream, void * Key, int KeySize, __int64 InCount = 0x000000000)/* overload */;
	__classmethod bool __fastcall IsConventionallyEncrypted(void * Buffer, int Size);
	__property int Algorithm = {read=FAlgorithm, nodefault};
	__property int BitsInKey = {read=FBitsInKey, nodefault};
	__property Sbpkcs7utils::TElPKCS7Issuer* CertIDs[int Index] = {read=GetCertIDs};
	__property int CertIDCount = {read=GetCertIDCount, nodefault};
	__property int UsedCertificate = {read=GetUsedCertificate, nodefault};
	__property bool UseOAEP = {read=FUseOAEP, nodefault};
	__property Sbcustomcertstorage::TElMemoryCertStorage* OriginatorCertificates = {read=FOriginatorCertificates};
	__property Sbcrlstorage::TElMemoryCRLStorage* OriginatorCRLs = {read=FOriginatorCRLs};
	__property Sbpkcs7utils::TElPKCS7Attributes* UnprotectedAttributes = {read=FUnprotectedAttributes};
	
__published:
	__property Sbcustomcertstorage::TElCustomCertStorage* CertStorage = {read=FCertStorage, write=SetCertStorage};
	__property TSBDecryptionOptions DecryptionOptions = {read=FDecryptionOptions, write=FDecryptionOptions, nodefault};
	__property TSBCertIDsEvent OnCertIDs = {read=FOnCertIDs, write=FOnCertIDs};
};

typedef TElMessageDecryptor ElMessageDecryptor
#pragma option push -b-
enum TSBMessageSignatureType { mstPublicKey, mstMAC };
#pragma option pop

#pragma option push -b-
enum TSBVerificationOption { voUseEmbeddedCerts, voUseLocalCerts, voVerifyMessageDigests, voVerifyTimestamps, voNoOuterContentInfo, voLiberalMode };
#pragma option pop

typedef Set<TSBVerificationOption, voUseEmbeddedCerts, voLiberalMode>  TSBVerificationOptions;

class DELPHICLASS TElMessageVerifier;
class PASCALIMPLEMENTATION TElMessageVerifier : public TElMessageProcessor
{
	typedef TElMessageProcessor inherited;
	
private:
	typedef DynamicArray<int> _TElMessageVerifier__1;
	
	
private:
	bool FUsePSS;
	Sbcustomcertstorage::TElCustomCertStorage* FCertStorage;
	Sbcustomcertstorage::TElMemoryCertStorage* FCertificates;
	Sbpkcs7utils::TElPKCS7Attributes* FAttributes;
	int FAlgorithm;
	int FMacAlgorithm;
	bool FVerifyCountersignatures;
	bool FInputIsDigest;
	Classes::TList* FCertIDs;
	Classes::TList* FCSCertIDs;
	Classes::TList* FCSAttributes;
	Classes::TList* FTimestamps;
	_TElMessageVerifier__1 FCSVerificationResults;
	TSBMessageSignatureType FSignatureType;
	TSBVerificationOptions FVerificationOptions;
	TSBCertIDsEvent FOnCertIDs;
	void __fastcall ExtractValuesFromAttributes(void);
	
protected:
	System::TDateTime FSigningTime;
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	int __fastcall VerifySingle(Sbpkcs7::TElPKCS7Signer* Signer, Sbpkcs7::TElPKCS7SignedData* Data, void * Digest, int DigestSize, Sbasn1tree::TElASN1DataSource* DataSource, bool Countersign = false);
	int __fastcall VerifyMessageDigests(Sbpkcs7::TElPKCS7Message* Msg, Classes::TStream* Stream, __int64 Offset, __int64 Count);
	int __fastcall VerifyTimestamps(Sbpkcs7::TElPKCS7Signer* Signer);
	void __fastcall ClearCertIDs(void);
	int __fastcall ExtractMACKey(Sbpkcs7::TElPKCS7AuthenticatedData* AuthData, Sbtypes::ByteArray &Key);
	void __fastcall ClearTimestamps(void);
	void __fastcall SetCertStorage(Sbcustomcertstorage::TElCustomCertStorage* Value);
	int __fastcall GetCertIDCount(void);
	int __fastcall GetCountersignatureCertIDCount(void);
	Sbtspclient::TElClientTSPInfo* __fastcall GetTimestamp(int Index);
	int __fastcall GetTimestampCount(void);
	Sbpkcs7utils::TElPKCS7Issuer* __fastcall GetCertIDs(int Index);
	Sbpkcs7utils::TElPKCS7Issuer* __fastcall GetCountersignatureCertIDs(int Index);
	int __fastcall GetCountersignatureVerificationResults(int Index);
	Sbpkcs7utils::TElPKCS7Attributes* __fastcall GetCountersignatureAttributes(int Index);
	void __fastcall ExtractCertificateIDs(Sbpkcs7::TElPKCS7Message* Msg, bool AuthData = false);
	void __fastcall Reset(void);
	int __fastcall VerifyAllSignatures(Sbpkcs7::TElPKCS7SignedData* Data, Sbutils::TElByteArrayList* Hashes);
	int __fastcall VerifyAllSignatures2(Sbpkcs7::TElPKCS7Message* Msg, Sbasn1tree::TElASN1DataSource* DataSource);
	Sbx509::TElX509Certificate* __fastcall FindSignerCertificate(Sbpkcs7::TElPKCS7Signer* Signer);
	int __fastcall InternalVerify(Classes::TStream* Source, Classes::TStream* Signature, Classes::TStream* Output, __int64 SourceCount = 0x000000000, __int64 SigCount = 0x000000000);
	
public:
	__fastcall virtual TElMessageVerifier(Classes::TComponent* AOwner);
	__fastcall virtual ~TElMessageVerifier(void);
	virtual int __fastcall Verify(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	virtual int __fastcall VerifyDetached(void * Buffer, int Size, void * Signature, int SignatureSize)/* overload */;
	__classmethod bool __fastcall IsSignatureDetached(void * Signature, int Size)/* overload */;
	__classmethod bool __fastcall IsSignatureDetached(Classes::TStream* Signature, __int64 Count = 0x000000000)/* overload */;
	int __fastcall Verify(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000)/* overload */;
	int __fastcall VerifyDetached(Classes::TStream* InStream, Classes::TStream* SigStream, __int64 InCount = 0x000000000, __int64 SigCount = 0x000000000)/* overload */;
	__property Sbcustomcertstorage::TElMemoryCertStorage* Certificates = {read=FCertificates};
	__property Sbpkcs7utils::TElPKCS7Attributes* Attributes = {read=FAttributes};
	__property int HashAlgorithm = {read=FAlgorithm, nodefault};
	__property int MacAlgorithm = {read=FMacAlgorithm, nodefault};
	__property Sbpkcs7utils::TElPKCS7Issuer* CertIDs[int Index] = {read=GetCertIDs};
	__property Sbpkcs7utils::TElPKCS7Issuer* CountersignatureCertIDs[int Index] = {read=GetCountersignatureCertIDs};
	__property int CountersignatureVerificationResults[int Index] = {read=GetCountersignatureVerificationResults};
	__property Sbpkcs7utils::TElPKCS7Attributes* CountersignatureAttributes[int Index] = {read=GetCountersignatureAttributes};
	__property int CertIDCount = {read=GetCertIDCount, nodefault};
	__property int CountersignatureCertIDCount = {read=GetCountersignatureCertIDCount, nodefault};
	__property TSBMessageSignatureType SignatureType = {read=FSignatureType, nodefault};
	__property bool UsePSS = {read=FUsePSS, nodefault};
	__property bool InputIsDigest = {read=FInputIsDigest, write=FInputIsDigest, default=0};
	__property Sbtspclient::TElClientTSPInfo* Timestamps[int Index] = {read=GetTimestamp};
	__property int TimestampCount = {read=GetTimestampCount, nodefault};
	__property System::TDateTime SigningTime = {read=FSigningTime};
	
__published:
	__property Sbcustomcertstorage::TElCustomCertStorage* CertStorage = {read=FCertStorage, write=SetCertStorage};
	__property bool VerifyCountersignatures = {read=FVerifyCountersignatures, write=FVerifyCountersignatures, nodefault};
	__property TSBVerificationOptions VerificationOptions = {read=FVerificationOptions, write=FVerificationOptions, default=7};
	__property TSBCertIDsEvent OnCertIDs = {read=FOnCertIDs, write=FOnCertIDs};
};

typedef TElMessageVerifier ElMessageVerifier
#pragma option push -b-
enum TSBSigningOption { soInsertMessageDigests, soIgnoreTimestampFailure, soNoOuterContentInfo, soRawCountersign, soInsertSigningTime, soUseGeneralizedTimeFormat, soIgnoreBadCountersignatures, soUseImplicitContent };
#pragma option pop

typedef Set<TSBSigningOption, soInsertMessageDigests, soUseImplicitContent>  TSBSigningOptions;

#pragma option push -b-
enum TSBSignOperationType { sotGeneric, sotAsyncPrepare, sotAsyncComplete };
#pragma option pop

class DELPHICLASS TElMessageSigner;
class PASCALIMPLEMENTATION TElMessageSigner : public TElMessageProcessor
{
	typedef TElMessageProcessor inherited;
	
private:
	bool FUsePSS;
	Sbcustomcertstorage::TElCustomCertStorage* FCertStorage;
	Sbcustomcertstorage::TElCustomCertStorage* FRecipientCerts;
	Sbpkcs7utils::TElPKCS7Attributes* FAAttributes;
	Sbpkcs7utils::TElPKCS7Attributes* FUAttributes;
	int FAlgorithm;
	int FMacAlgorithm;
	bool FIncludeCertificates;
	bool FIncludeChain;
	TSBMessageSignatureType FSignatureType;
	Sbtypes::ByteArray FContentType;
	bool FUseUndefSize;
	TSBSigningOptions FSigningOptions;
	Sbtypes::ByteArray FDigestEncryptionAlgorithm;
	System::TDateTime FSigningTime;
	Sbtypes::ByteArray FDataHash;
	TSBSignOperationType FOperationType;
	int FExtraSpace;
	Sbtspclient::TElCustomTSPClient* FTSPClient;
	
protected:
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	int __fastcall FillSigner(Sbpkcs7::TElPKCS7Signer* Signer, Sbx509::TElX509Certificate* Certificate, const Sbtypes::ByteArray DigestAlgorithm, void * Hash, int HashSize);
	bool __fastcall SignDSA(Sbx509::TElX509Certificate* Certificate, void * Digest, int DigestSize, Sbtypes::ByteArray &Signature);
	bool __fastcall SignRSAPSS(Sbx509::TElX509Certificate* Certificate, void * Digest, int DigestSize, Sbtypes::ByteArray &Signature);
	bool __fastcall SignEC(Sbpkcs7::TElPKCS7Signer* Signer, Sbx509::TElX509Certificate* Certificate, void * Digest, int DigestSize, Sbtypes::ByteArray &Signature);
	bool __fastcall SignGOST2001(Sbpkcs7::TElPKCS7Signer* Signer, Sbx509::TElX509Certificate* Certificate, void * Digest, int DigestSize, Sbtypes::ByteArray &Signature);
	int __fastcall CalculateEstimatedSize(int InputSize, bool Detached);
	int __fastcall TimestampMessage(Sbpkcs7::TElPKCS7Message* Msg);
	int __fastcall TimestampCountersignatures(Sbpkcs7::TElPKCS7Message* Msg, int *SigIndexes, const int SigIndexes_Size);
	int __fastcall TimestampSignerInfo(Sbpkcs7::TElPKCS7Signer* SignerInfo);
	int __fastcall SignPublicKey(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount, bool Detached);
	int __fastcall SignMAC(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount, bool Detached);
	int __fastcall InternalCountersign(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount);
	void __fastcall SetCertStorage(Sbcustomcertstorage::TElCustomCertStorage* Value);
	void __fastcall SetRecipientCerts(Sbcustomcertstorage::TElCustomCertStorage* Value);
	void __fastcall SetTSPClient(Sbtspclient::TElCustomTSPClient* Value);
	void __fastcall SetContentType(const Sbtypes::ByteArray V);
	void __fastcall SetDigestEncryptionAlgorithm(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual TElMessageSigner(Classes::TComponent* AOwner);
	__fastcall virtual ~TElMessageSigner(void);
	virtual int __fastcall Sign(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, bool Detached = false)/* overload */;
	virtual int __fastcall Sign(Classes::TStream* InStream, Classes::TStream* OutStream, bool Detached = false, __int64 InCount = 0x000000000)/* overload */;
	virtual int __fastcall Countersign(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	virtual int __fastcall Countersign(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000)/* overload */;
	int __fastcall Timestamp(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	int __fastcall Timestamp(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000)/* overload */;
	int __fastcall TimestampCountersignature(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, int SigIndex)/* overload */;
	int __fastcall TimestampCountersignature(Classes::TStream* InStream, Classes::TStream* OutStream, int SigIndex, __int64 InCount = 0x000000000)/* overload */;
	__property Sbpkcs7utils::TElPKCS7Attributes* AuthenticatedAttributes = {read=FAAttributes};
	__property Sbpkcs7utils::TElPKCS7Attributes* UnauthenticatedAttributes = {read=FUAttributes};
	__property int HashAlgorithm = {read=FAlgorithm, write=FAlgorithm, nodefault};
	__property int MacAlgorithm = {read=FMacAlgorithm, write=FMacAlgorithm, nodefault};
	__property Sbtypes::ByteArray ContentType = {read=FContentType, write=SetContentType};
	__property Sbtypes::ByteArray DataHash = {read=FDataHash};
	__property Sbtypes::ByteArray DigestEncryptionAlgorithm = {read=FDigestEncryptionAlgorithm, write=SetDigestEncryptionAlgorithm};
	__property System::TDateTime SigningTime = {read=FSigningTime, write=FSigningTime};
	
__published:
	__property TSBMessageSignatureType SignatureType = {read=FSignatureType, write=FSignatureType, default=0};
	__property Sbcustomcertstorage::TElCustomCertStorage* CertStorage = {read=FCertStorage, write=SetCertStorage};
	__property bool IncludeCertificates = {read=FIncludeCertificates, write=FIncludeCertificates, default=1};
	__property bool IncludeChain = {read=FIncludeChain, write=FIncludeChain, default=0};
	__property Sbcustomcertstorage::TElCustomCertStorage* RecipientCerts = {read=FRecipientCerts, write=SetRecipientCerts};
	__property bool UseUndefSize = {read=FUseUndefSize, write=FUseUndefSize, default=1};
	__property bool UsePSS = {read=FUsePSS, write=FUsePSS, nodefault};
	__property TSBSigningOptions SigningOptions = {read=FSigningOptions, write=FSigningOptions, default=1};
	__property int ExtraSpace = {read=FExtraSpace, write=FExtraSpace, nodefault};
	__property Sbtspclient::TElCustomTSPClient* TSPClient = {read=FTSPClient, write=SetTSPClient};
};

typedef TElMessageSigner ElMessageSigner
class DELPHICLASS TElMessageDecompressor;
class PASCALIMPLEMENTATION TElMessageDecompressor : public TElMessageProcessor
{
	typedef TElMessageProcessor inherited;
	
private:
	Sbtypes::ByteArray FZLibSpool;
	Sbtypes::ByteArray FContentType;
	bool __fastcall ZLibOutput(void * Buffer, int Size, void * Param);
	
protected:
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	bool __fastcall DecompressContent(void * InBuffer, int InSize, void * OutBuffer, int &OutSize);
	Classes::TStream* __fastcall CreateDecompressingStream(Sbpkcs7::TElPKCS7CompressedData* Source);
	void __fastcall OnDecompressingStreamProgress(System::TObject* Sender, __int64 Total, __int64 Current, bool &Cancel);
	
public:
	__fastcall virtual TElMessageDecompressor(Classes::TComponent* AOwner);
	__fastcall virtual ~TElMessageDecompressor(void);
	int __fastcall Decompress(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	int __fastcall Decompress(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000)/* overload */;
	__property Sbtypes::ByteArray ContentType = {read=FContentType};
};


class DELPHICLASS TElMessageCompressor;
class PASCALIMPLEMENTATION TElMessageCompressor : public TElMessageProcessor
{
	typedef TElMessageProcessor inherited;
	
private:
	bool FUseUndefSize;
	Sbtypes::ByteArray FContentToCompress;
	Sbtypes::ByteArray FCompressedContent;
	Sbtypes::ByteArray FContentType;
	int FCompressionLevel;
	int FFragmentSize;
	
protected:
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	void __fastcall CompressContent(void * InBuffer, int InSize, int CompressionLevel);
	Classes::TStream* __fastcall CreateCompressingStream(Classes::TStream* Source);
	void __fastcall OnCompressingStreamProgress(System::TObject* Sender, __int64 Total, __int64 Current, bool &Cancel);
	void __fastcall SetContentType(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual TElMessageCompressor(Classes::TComponent* AOwner);
	__fastcall virtual ~TElMessageCompressor(void);
	int __fastcall Compress(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	int __fastcall Compress(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000)/* overload */;
	__property Sbtypes::ByteArray ContentType = {read=FContentType, write=SetContentType};
	__property int CompressionLevel = {read=FCompressionLevel, write=FCompressionLevel, nodefault};
	__property int FragmentSize = {read=FFragmentSize, write=FFragmentSize, nodefault};
	
__published:
	__property bool UseUndefSize = {read=FUseUndefSize, write=FUseUndefSize, default=1};
};


class DELPHICLASS TElMessageTimestamper;
class PASCALIMPLEMENTATION TElMessageTimestamper : public TElMessageProcessor
{
	typedef TElMessageProcessor inherited;
	
private:
	bool FIncludeContent;
	bool FProtectMetadata;
	System::UnicodeString FDataURI;
	System::UnicodeString FFileName;
	System::UnicodeString FMediaType;
	bool FUseUndefSize;
	Sbutils::TSBObjectList* FTSPClientList;
	
protected:
	Sbtspclient::TElCustomTSPClient* __fastcall GetTSPClients(int Index);
	int __fastcall GetTSPClientsCount(void);
	Sbtspclient::TElCustomTSPClient* __fastcall GetTSPClient(void);
	void __fastcall SetTSPClient(Sbtspclient::TElCustomTSPClient* Client);
	int __fastcall CalculateEstimatedSize(int InputSize);
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	
public:
	__fastcall virtual TElMessageTimestamper(Classes::TComponent* AOwner);
	__fastcall virtual ~TElMessageTimestamper(void);
	int __fastcall Timestamp(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	int __fastcall Timestamp(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000)/* overload */;
	int __fastcall AddTSPClient(Sbtspclient::TElCustomTSPClient* Client);
	void __fastcall RemoveTSPClient(int Index)/* overload */;
	void __fastcall RemoveTSPClient(Sbtspclient::TElCustomTSPClient* Client)/* overload */;
	__property Sbtspclient::TElCustomTSPClient* TSPClients[int Index] = {read=GetTSPClients};
	__property int TSPClientsCount = {read=GetTSPClientsCount, nodefault};
	__property Sbtspclient::TElCustomTSPClient* TSPClient = {read=GetTSPClient, write=SetTSPClient};
	
__published:
	__property bool IncludeContent = {read=FIncludeContent, write=FIncludeContent, nodefault};
	__property bool ProtectMetadata = {read=FProtectMetadata, write=FProtectMetadata, nodefault};
	__property System::UnicodeString DataURI = {read=FDataURI, write=FDataURI};
	__property System::UnicodeString FileName = {read=FFileName, write=FFileName};
	__property System::UnicodeString MediaType = {read=FMediaType, write=FMediaType};
	__property bool UseUndefSize = {read=FUseUndefSize, write=FUseUndefSize, default=1};
};


class DELPHICLASS TElMessageTimestampVerifier;
class PASCALIMPLEMENTATION TElMessageTimestampVerifier : public TElMessageProcessor
{
	typedef TElMessageProcessor inherited;
	
private:
	System::UnicodeString FDataURI;
	System::UnicodeString FFileName;
	System::UnicodeString FMediaType;
	Classes::TList* FTimestamps;
	
protected:
	Sbtspclient::TElClientTSPInfo* __fastcall GetTimestamp(int Index);
	int __fastcall GetTimestampCount(void);
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	bool __fastcall ParseMessageImprint(const Sbtypes::ByteArray Imprint, Sbtypes::ByteArray &HashAlgOID, Sbtypes::ByteArray &Hash);
	int __fastcall InternalVerify(Classes::TStream* InStream, Classes::TStream* DataStream, Classes::TStream* OutStream, __int64 InCount, __int64 DataCount);
	
public:
	__fastcall virtual TElMessageTimestampVerifier(Classes::TComponent* AOwner);
	__fastcall virtual ~TElMessageTimestampVerifier(void);
	virtual int __fastcall Verify(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	virtual int __fastcall VerifyDetached(void * Buffer, int Size, void * Data, int DataSize)/* overload */;
	__classmethod bool __fastcall IsTimestampDetached(void * Timestamp, int Size, System::UnicodeString &DataURI, System::UnicodeString &FileName)/* overload */;
	__classmethod bool __fastcall IsTimestampDetached(Classes::TStream* Timestamp, System::UnicodeString &DataURI, System::UnicodeString &FileName, __int64 Count = 0x000000000)/* overload */;
	int __fastcall Verify(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000)/* overload */;
	int __fastcall VerifyDetached(Classes::TStream* InStream, Classes::TStream* DataStream, __int64 InCount = 0x000000000, __int64 DataCount = 0x000000000)/* overload */;
	__property Sbtspclient::TElClientTSPInfo* Timestamps[int Index] = {read=GetTimestamp};
	__property int TimestampCount = {read=GetTimestampCount, nodefault};
	__property System::UnicodeString DataURI = {read=FDataURI};
	__property System::UnicodeString FileName = {read=FFileName};
	__property System::UnicodeString MediaType = {read=FMediaType};
};


class DELPHICLASS EElMessageError;
class PASCALIMPLEMENTATION EElMessageError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElMessageError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElMessageError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElMessageError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElMessageError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElMessageError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElMessageError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElMessageError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElMessageError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElMessageError(void) { }
	
};


class DELPHICLASS EElMessageUserCancelledError;
class PASCALIMPLEMENTATION EElMessageUserCancelledError : public EElMessageError
{
	typedef EElMessageError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElMessageUserCancelledError(const System::UnicodeString AMessage)/* overload */ : EElMessageError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElMessageUserCancelledError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElMessageError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElMessageUserCancelledError(int Ident)/* overload */ : EElMessageError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElMessageUserCancelledError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElMessageError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElMessageUserCancelledError(const System::UnicodeString Msg, int AHelpContext) : EElMessageError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElMessageUserCancelledError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElMessageError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElMessageUserCancelledError(int Ident, int AHelpContext)/* overload */ : EElMessageError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElMessageUserCancelledError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElMessageError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElMessageUserCancelledError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const int SB_MESSAGE_ERROR_NO_ENCRYPTED_DATA = 8193;
static const int SB_MESSAGE_ERROR_NO_CERTIFICATE = 8194;
static const int SB_MESSAGE_ERROR_KEY_DECRYPTION_FAILED = 8195;
static const int SB_MESSAGE_ERROR_BUFFER_TOO_SMALL = 8196;
static const int SB_MESSAGE_ERROR_CONTENT_DECRYPTION_FAILED = 8197;
static const int SB_MESSAGE_ERROR_INVALID_FORMAT = 8198;
static const int SB_MESSAGE_ERROR_NO_RECIPIENTS = 8199;
static const int SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM = 8200;
static const int SB_MESSAGE_ERROR_ENCRYPTION_FAILED = 8201;
static const int SB_MESSAGE_ERROR_INVALID_KEY_LENGTH = 8202;
static const int SB_MESSAGE_ERROR_NO_SIGNED_DATA = 8203;
static const int SB_MESSAGE_ERROR_INVALID_SIGNATURE = 8204;
static const int SB_MESSAGE_ERROR_INVALID_DIGEST = 8205;
static const int SB_MESSAGE_ERROR_SIGNING_FAILED = 8206;
static const int SB_MESSAGE_ERROR_INTERNAL_ERROR = 8207;
static const int SB_MESSAGE_ERROR_INVALID_MAC = 8208;
static const int SB_MESSAGE_ERROR_UNSUPPORTED_SIGNATURE_TYPE = 8209;
static const int SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE = 8210;
static const int SB_MESSAGE_ERROR_DIGEST_NOT_FOUND = 8211;
static const int SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM = 8212;
static const int SB_MESSAGE_ERROR_CANCELLED_BY_USER = 8213;
static const int SB_MESSAGE_ERROR_VERIFICATION_FAILED = 8214;
static const int SB_MESSAGE_ERROR_DIGEST_CALCULATION_FAILED = 8215;
static const int SB_MESSAGE_ERROR_MAC_CALCULATION_FAILED = 8216;
static const int SB_MESSAGE_ERROR_TSPCLIENT_NOT_FOUND = 8217;
static const int SB_MESSAGE_ERROR_BAD_TIMESTAMP = 8218;
static const int SB_MESSAGE_ERROR_KEYOP_FAILED_RSA = 8219;
static const int SB_MESSAGE_ERROR_KEYOP_FAILED_DSA = 8220;
static const int SB_MESSAGE_ERROR_KEYOP_FAILED_RSA_PSS = 8221;
static const int SB_MESSAGE_ERROR_NO_COMPRESSED_DATA = 8222;
static const int SB_MESSAGE_ERROR_KEYOP_FAILED_EC = 8223;
static const int SB_MESSAGE_ERROR_DC_BAD_ASYNC_STATE = 8224;
static const int SB_MESSAGE_ERROR_DC_SERVER_ERROR = 8225;
static const int SB_MESSAGE_ERROR_DC_MODULE_UNAVAILABLE = 8226;
static const int SB_MESSAGE_ERROR_KEYOP_FAILED_GOST = 8227;
static const int SB_MESSAGE_ERROR_NO_CONTENT_OR_DATA_URI = 8228;
static const int SB_MESSAGE_ERROR_TIMESTAMPING_FAILED = 8229;
static const int SB_MESSAGE_ERROR_NO_TIMESTAMPED_DATA = 8230;
extern PACKAGE void __fastcall Register(void);

}	/* namespace Sbmessages */
using namespace Sbmessages;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbmessagesHPP
