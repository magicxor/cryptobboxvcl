// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpkcs7.pas' rev: 21.00

#ifndef Sbpkcs7HPP
#define Sbpkcs7HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbpkcs7utils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbstreams.hpp>	// Pascal unit
#include <Sbalgorithmidentifier.hpp>	// Pascal unit
#include <Sbcrl.hpp>	// Pascal unit
#include <Sbcrlstorage.hpp>	// Pascal unit
#include <Sbocspcommon.hpp>	// Pascal unit
#include <Sbocspclient.hpp>	// Pascal unit
#include <Sbocspstorage.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpkcs7
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBPKCS7ContentType { ctData, ctSignedData, ctEnvelopedData, ctSignedAndEnvelopedData, ctDigestedData, ctEncryptedData, ctAuthenticatedData, ctCompressedData, ctTimestampedData, ctUnknown };
#pragma option pop

class DELPHICLASS TElPKCS7Recipient;
class PASCALIMPLEMENTATION TElPKCS7Recipient : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FVersion;
	Sbpkcs7utils::TElPKCS7Issuer* FIssuer;
	Sbtypes::ByteArray FKeyEncryptionAlgorithm;
	Sbtypes::ByteArray FKeyEncryptionAlgorithmParams;
	Sbalgorithmidentifier::TElAlgorithmIdentifier* FKeyEncryptionAlgorithmIdentifier;
	Sbtypes::ByteArray FEncryptedKey;
	void __fastcall SetKeyEncryptionAlgorithm(const Sbtypes::ByteArray V);
	void __fastcall SetKeyEncryptionAlgorithmParams(const Sbtypes::ByteArray V);
	void __fastcall SetEncryptedKey(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElPKCS7Recipient(void);
	__fastcall virtual ~TElPKCS7Recipient(void);
	__property int Version = {read=FVersion, write=FVersion, nodefault};
	__property Sbpkcs7utils::TElPKCS7Issuer* Issuer = {read=FIssuer};
	__property Sbtypes::ByteArray KeyEncryptionAlgorithm = {read=FKeyEncryptionAlgorithm, write=SetKeyEncryptionAlgorithm};
	__property Sbtypes::ByteArray KeyEncryptionAlgorithmParams = {read=FKeyEncryptionAlgorithmParams, write=SetKeyEncryptionAlgorithmParams};
	__property Sbalgorithmidentifier::TElAlgorithmIdentifier* KeyEncryptionAlgorithmIdentifier = {read=FKeyEncryptionAlgorithmIdentifier, write=FKeyEncryptionAlgorithmIdentifier};
	__property Sbtypes::ByteArray EncryptedKey = {read=FEncryptedKey, write=SetEncryptedKey};
};


class DELPHICLASS TElPKCS7ContentPart;
class PASCALIMPLEMENTATION TElPKCS7ContentPart : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Classes::TStream* FStream;
	int FOffset;
	int FSize;
	Sbtypes::ByteArray FContent;
	int __fastcall GetSize(void);
	
public:
	__fastcall virtual ~TElPKCS7ContentPart(void);
	int __fastcall Read(void * Buffer, int Size, int StartOffset = 0x0);
	__property int Size = {read=GetSize, nodefault};
public:
	/* TObject.Create */ inline __fastcall TElPKCS7ContentPart(void) : System::TObject() { }
	
};


class DELPHICLASS TElPKCS7EncryptedContent;
class PASCALIMPLEMENTATION TElPKCS7EncryptedContent : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbtypes::ByteArray FContentType;
	Sbtypes::ByteArray FContentEncryptionAlgorithm;
	Sbtypes::ByteArray FContentEncryptionAlgorithmParams;
	bool FUseImplicitContentEncoding;
	Classes::TList* FEncryptedContentParts;
	int __fastcall AddContentPart(Sbasn1tree::TElASN1DataSource* DataSource)/* overload */;
	int __fastcall AddContentPart(const Sbtypes::ByteArray Value)/* overload */;
	void __fastcall ClearContentParts(void);
	int __fastcall GetEncryptedContentPartCount(void);
	Sbtypes::ByteArray __fastcall GetEncryptedContent(void);
	void __fastcall SetEncryptedContent(const Sbtypes::ByteArray Value);
	Sbasn1tree::TElASN1DataSource* __fastcall GetDataSource(void);
	void __fastcall SetContentType(const Sbtypes::ByteArray V);
	void __fastcall SetContentEncryptionAlgorithm(const Sbtypes::ByteArray V);
	void __fastcall SetContentEncryptionAlgorithmParams(const Sbtypes::ByteArray V);
	Sbasn1tree::TElASN1DataSource* __fastcall GetEncryptedContentPart(int Index);
	
public:
	__fastcall TElPKCS7EncryptedContent(void);
	__fastcall virtual ~TElPKCS7EncryptedContent(void);
	__property Sbtypes::ByteArray ContentType = {read=FContentType, write=SetContentType};
	__property Sbtypes::ByteArray ContentEncryptionAlgorithm = {read=FContentEncryptionAlgorithm, write=SetContentEncryptionAlgorithm};
	__property Sbtypes::ByteArray ContentEncryptionAlgorithmParams = {read=FContentEncryptionAlgorithmParams, write=SetContentEncryptionAlgorithmParams};
	__property Sbtypes::ByteArray EncryptedContent = {read=GetEncryptedContent, write=SetEncryptedContent};
	__property Sbasn1tree::TElASN1DataSource* EncryptedContentParts[int Index] = {read=GetEncryptedContentPart};
	__property int EncryptedContentPartCount = {read=GetEncryptedContentPartCount, nodefault};
	__property Sbasn1tree::TElASN1DataSource* DataSource = {read=GetDataSource};
	__property bool UseImplicitContentEncoding = {read=FUseImplicitContentEncoding, write=FUseImplicitContentEncoding, nodefault};
};


class DELPHICLASS TElPKCS7EnvelopedData;
class DELPHICLASS TElPKCS7Message;
class PASCALIMPLEMENTATION TElPKCS7EnvelopedData : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FVersion;
	Classes::TList* FRecipientList;
	TElPKCS7EncryptedContent* FEncryptedContent;
	int FContentEncryptionAlgorithm;
	bool FCMSFormat;
	Sbcustomcertstorage::TElMemoryCertStorage* FOriginatorCertificates;
	Sbcrlstorage::TElMemoryCRLStorage* FOriginatorCRLs;
	Sbpkcs7utils::TElPKCS7Attributes* FUnprotectedAttributes;
	TElPKCS7Message* FOwner;
	int __fastcall GetRecipientCount(void);
	void __fastcall Clear(void);
	TElPKCS7Recipient* __fastcall GetRecipient(int Index);
	
public:
	__fastcall TElPKCS7EnvelopedData(void);
	__fastcall virtual ~TElPKCS7EnvelopedData(void);
	int __fastcall AddRecipient(void);
	bool __fastcall RemoveRecipient(int Index);
	bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	__property int Version = {read=FVersion, write=FVersion, nodefault};
	__property TElPKCS7Recipient* Recipients[int Index] = {read=GetRecipient};
	__property int RecipientCount = {read=GetRecipientCount, nodefault};
	__property TElPKCS7EncryptedContent* EncryptedContent = {read=FEncryptedContent, write=FEncryptedContent};
	__property int ContentEncryptionAlgorithm = {read=FContentEncryptionAlgorithm, write=FContentEncryptionAlgorithm, nodefault};
	__property bool CMSFormat = {read=FCMSFormat, write=FCMSFormat, nodefault};
	__property Sbcustomcertstorage::TElMemoryCertStorage* OriginatorCertificates = {read=FOriginatorCertificates};
	__property Sbcrlstorage::TElMemoryCRLStorage* OriginatorCRLs = {read=FOriginatorCRLs};
	__property Sbpkcs7utils::TElPKCS7Attributes* UnprotectedAttributes = {read=FUnprotectedAttributes};
};


class DELPHICLASS TElPKCS7CompressedData;
class PASCALIMPLEMENTATION TElPKCS7CompressedData : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FVersion;
	Sbtypes::ByteArray FContentType;
	Classes::TList* FCompressedContentParts;
	TElPKCS7Message* FOwner;
	int FFragmentSize;
	int __fastcall AddContentPart(Sbasn1tree::TElASN1DataSource* DataSource)/* overload */;
	int __fastcall AddContentPart(const Sbtypes::ByteArray Value)/* overload */;
	void __fastcall ClearContentParts(void);
	int __fastcall GetCompressedContentPartCount(void);
	Sbtypes::ByteArray __fastcall GetCompressedContent(void);
	void __fastcall SetCompressedContent(const Sbtypes::ByteArray Value);
	Sbasn1tree::TElASN1DataSource* __fastcall GetDataSource(void);
	void __fastcall SetContentType(const Sbtypes::ByteArray V);
	Sbasn1tree::TElASN1DataSource* __fastcall GetCompressedContentPart(int Index);
	
public:
	__fastcall TElPKCS7CompressedData(void);
	__fastcall virtual ~TElPKCS7CompressedData(void);
	bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	__property int Version = {read=FVersion, write=FVersion, nodefault};
	__property Sbtypes::ByteArray ContentType = {read=FContentType, write=SetContentType};
	__property Sbtypes::ByteArray CompressedContent = {read=GetCompressedContent, write=SetCompressedContent};
	__property Sbasn1tree::TElASN1DataSource* CompressedContentParts[int Index] = {read=GetCompressedContentPart};
	__property int CompressedContentPartCount = {read=GetCompressedContentPartCount, nodefault};
	__property int FragmentSize = {read=FFragmentSize, write=FFragmentSize, nodefault};
	__property Sbasn1tree::TElASN1DataSource* DataSource = {read=GetDataSource};
};


class DELPHICLASS TElPKCS7Signer;
class PASCALIMPLEMENTATION TElPKCS7Signer : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FVersion;
	Sbpkcs7utils::TElPKCS7Issuer* FIssuer;
	Sbtypes::ByteArray FDigestAlgorithm;
	Sbtypes::ByteArray FDigestAlgorithmParams;
	Sbpkcs7utils::TElPKCS7Attributes* FAuthenticatedAttributes;
	Sbpkcs7utils::TElPKCS7Attributes* FUnauthenticatedAttributes;
	Sbtypes::ByteArray FDigestEncryptionAlgorithm;
	Sbtypes::ByteArray FDigestEncryptionAlgorithmParams;
	Sbtypes::ByteArray FEncryptedDigest;
	Sbtypes::ByteArray FAuthenticatedAttributesPlain;
	Sbtypes::ByteArray FContent;
	Sbtypes::ByteArray FEncodedValue;
	Sbtypes::ByteArray FArchivalEncodedValue;
	bool FWriteNullInDigestEncryptionAlgID;
	
protected:
	Sbtypes::ByteArray __fastcall GetAuthenticatedAttributesPlain(void);
	void __fastcall SetDigestAlgorithm(const Sbtypes::ByteArray V);
	void __fastcall SetDigestAlgorithmParams(const Sbtypes::ByteArray V);
	void __fastcall SetDigestEncryptionAlgorithm(const Sbtypes::ByteArray V);
	void __fastcall SetDigestEncryptionAlgorithmParams(const Sbtypes::ByteArray V);
	void __fastcall SetEncryptedDigest(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElPKCS7Signer(void);
	__fastcall virtual ~TElPKCS7Signer(void);
	void __fastcall RecalculateAuthenticatedAttributes(void)/* overload */;
	void __fastcall RecalculateAuthenticatedAttributes(bool Reorder)/* overload */;
	void __fastcall Recalculate(void);
	void __fastcall Assign(TElPKCS7Signer* Source);
	__property int Version = {read=FVersion, write=FVersion, nodefault};
	__property Sbpkcs7utils::TElPKCS7Issuer* Issuer = {read=FIssuer};
	__property Sbtypes::ByteArray DigestAlgorithm = {read=FDigestAlgorithm, write=SetDigestAlgorithm};
	__property Sbtypes::ByteArray DigestAlgorithmParams = {read=FDigestAlgorithmParams, write=SetDigestAlgorithmParams};
	__property Sbtypes::ByteArray DigestEncryptionAlgorithm = {read=FDigestEncryptionAlgorithm, write=SetDigestEncryptionAlgorithm};
	__property Sbtypes::ByteArray DigestEncryptionAlgorithmParams = {read=FDigestEncryptionAlgorithmParams, write=SetDigestEncryptionAlgorithmParams};
	__property Sbpkcs7utils::TElPKCS7Attributes* AuthenticatedAttributes = {read=FAuthenticatedAttributes};
	__property Sbpkcs7utils::TElPKCS7Attributes* UnauthenticatedAttributes = {read=FUnauthenticatedAttributes};
	__property Sbtypes::ByteArray EncryptedDigest = {read=FEncryptedDigest, write=SetEncryptedDigest};
	__property Sbtypes::ByteArray AuthenticatedAttributesPlain = {read=GetAuthenticatedAttributesPlain};
	__property Sbtypes::ByteArray Content = {read=FContent};
	__property Sbtypes::ByteArray EncodedValue = {read=FEncodedValue};
	__property Sbtypes::ByteArray ArchivalEncodedValue = {read=FArchivalEncodedValue};
};


class DELPHICLASS TElPKCS7SignedData;
class PASCALIMPLEMENTATION TElPKCS7SignedData : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FVersion;
	Classes::TList* FSignerList;
	Sbcustomcertstorage::TElMemoryCertStorage* FCertStorage;
	Sbcrlstorage::TElMemoryCRLStorage* FCRLStorage;
	Sbocspstorage::TElOCSPResponseStorage* FOCSPStorage;
	TElPKCS7Message* FOwner;
	Sbtypes::ByteArray FEncodedCertificates;
	Sbtypes::ByteArray FEncodedCRLs;
	Sbtypes::ByteArray FEnvelopedContentPrefix;
	Sbtypes::ByteArray FEnvelopedContentPostfix;
	Sbtypes::ByteArray FContentType;
	Classes::TList* FContentParts;
	Classes::TMemoryStream* FCurrContentSerializationStream;
	__int64 FCurrContentSerializationStartOffset;
	__int64 FCurrContentSerializationEndOffset;
	bool FIsMultipart;
	Sbtypes::ByteArray FRawMultipartContent;
	bool FPreserveCachedContent;
	bool FPreserveCachedElements;
	int __fastcall AddContentPart(Sbasn1tree::TElASN1DataSource* DataSource)/* overload */;
	int __fastcall AddContentPart(const Sbtypes::ByteArray Data)/* overload */;
	int __fastcall AddContentPart(void * Buffer, int Size)/* overload */;
	int __fastcall GetSignerCount(void);
	int __fastcall GetContentPartCount(void);
	Sbtypes::ByteArray __fastcall GetContent(void);
	void __fastcall SetContent(const Sbtypes::ByteArray Value);
	Sbasn1tree::TElASN1DataSource* __fastcall GetDataSource(void);
	void __fastcall SetContentType(const Sbtypes::ByteArray V);
	void __fastcall SerializeCertsAndCRLs(void);
	void __fastcall SerializeEnvelopedContent(void);
	void __fastcall HandleContentTagContentWriteBegin(System::TObject* Sender);
	void __fastcall HandleContentTagContentWriteEnd(System::TObject* Sender);
	TElPKCS7Signer* __fastcall GetSigner(int Index);
	Sbasn1tree::TElASN1DataSource* __fastcall GetContentPart(int Index);
	
public:
	__fastcall TElPKCS7SignedData(void);
	__fastcall virtual ~TElPKCS7SignedData(void);
	int __fastcall AddContentPart(void)/* overload */;
	void __fastcall ClearContentParts(void);
	int __fastcall AddSigner(void);
	bool __fastcall RemoveSigner(int Index);
	bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	void __fastcall SaveToStream(Classes::TStream* Stream);
	void __fastcall PreSerialize(bool SerializeContent, bool SerializeCertsAndCrls);
	__property int Version = {read=FVersion, write=FVersion, nodefault};
	__property TElPKCS7Signer* Signers[int Index] = {read=GetSigner};
	__property Sbasn1tree::TElASN1DataSource* ContentParts[int Index] = {read=GetContentPart};
	__property int SignerCount = {read=GetSignerCount, nodefault};
	__property Sbcustomcertstorage::TElMemoryCertStorage* Certificates = {read=FCertStorage};
	__property Sbcrlstorage::TElMemoryCRLStorage* CRLs = {read=FCRLStorage};
	__property Sbocspstorage::TElOCSPResponseStorage* OCSPs = {read=FOCSPStorage};
	__property Sbtypes::ByteArray Content = {read=GetContent, write=SetContent};
	__property Sbtypes::ByteArray ContentType = {read=FContentType, write=SetContentType};
	__property int ContentPartCount = {read=GetContentPartCount, nodefault};
	__property Sbasn1tree::TElASN1DataSource* DataSource = {read=GetDataSource};
	__property Sbtypes::ByteArray EncodedCertificates = {read=FEncodedCertificates};
	__property Sbtypes::ByteArray EncodedCRLs = {read=FEncodedCRLs};
	__property Sbtypes::ByteArray EnvelopedContentPrefix = {read=FEnvelopedContentPrefix};
	__property Sbtypes::ByteArray EnvelopedContentPostfix = {read=FEnvelopedContentPostfix};
	__property bool IsMultipart = {read=FIsMultipart, nodefault};
	__property Sbtypes::ByteArray RawMultipartContent = {read=FRawMultipartContent};
	__property bool PreserveCachedContent = {read=FPreserveCachedContent, write=FPreserveCachedContent, nodefault};
	__property bool PreserveCachedElements = {read=FPreserveCachedElements, write=FPreserveCachedElements, nodefault};
};


class DELPHICLASS TElPKCS7DigestedData;
class PASCALIMPLEMENTATION TElPKCS7DigestedData : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FVersion;
	Sbtypes::ByteArray FDigestAlgorithm;
	Sbtypes::ByteArray FDigestAlgorithmParams;
	Sbtypes::ByteArray FContent;
	Sbtypes::ByteArray FDigest;
	void __fastcall SetDigestAlgorithm(const Sbtypes::ByteArray V);
	void __fastcall SetDigestAlgorithmParams(const Sbtypes::ByteArray V);
	void __fastcall SetContent(const Sbtypes::ByteArray V);
	void __fastcall SetDigest(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual ~TElPKCS7DigestedData(void);
	__property Sbtypes::ByteArray DigestAlgorithm = {read=FDigestAlgorithm, write=SetDigestAlgorithm};
	__property Sbtypes::ByteArray DigestAlgorithmParams = {read=FDigestAlgorithmParams, write=SetDigestAlgorithmParams};
	__property Sbtypes::ByteArray Content = {read=FContent, write=SetContent};
	__property Sbtypes::ByteArray Digest = {read=FDigest, write=SetDigest};
	__property int Version = {read=FVersion, write=FVersion, nodefault};
public:
	/* TObject.Create */ inline __fastcall TElPKCS7DigestedData(void) : System::TObject() { }
	
};


class DELPHICLASS TElPKCS7EncryptedData;
class PASCALIMPLEMENTATION TElPKCS7EncryptedData : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FVersion;
	TElPKCS7EncryptedContent* FEncryptedContent;
	TElPKCS7Message* FOwner;
	
public:
	__fastcall TElPKCS7EncryptedData(void);
	__fastcall virtual ~TElPKCS7EncryptedData(void);
	bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	__property int Version = {read=FVersion, write=FVersion, nodefault};
	__property TElPKCS7EncryptedContent* EncryptedContent = {read=FEncryptedContent};
};


class DELPHICLASS TElPKCS7SignedAndEnvelopedData;
class PASCALIMPLEMENTATION TElPKCS7SignedAndEnvelopedData : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FVersion;
	Classes::TList* FRecipientList;
	Classes::TList* FSignerList;
	TElPKCS7EncryptedContent* FEncryptedContent;
	Sbcustomcertstorage::TElMemoryCertStorage* FCertStorage;
	
public:
	__fastcall TElPKCS7SignedAndEnvelopedData(void);
	__fastcall virtual ~TElPKCS7SignedAndEnvelopedData(void);
	TElPKCS7Recipient* __fastcall GetRecipient(int Index);
	int __fastcall GetRecipientCount(void);
	TElPKCS7Signer* __fastcall GetSigner(int Index);
	int __fastcall GetSignerCount(void);
	int __fastcall AddRecipient(void);
	int __fastcall AddSigner(void);
	bool __fastcall RemoveRecipient(int Index);
	bool __fastcall RemoveSigner(int Index);
	__property int Version = {read=FVersion, write=FVersion, nodefault};
	__property TElPKCS7Recipient* Recipients[int Index] = {read=GetRecipient};
	__property TElPKCS7Signer* Signers[int Index] = {read=GetSigner};
	__property int RecipientCount = {read=GetRecipientCount, nodefault};
	__property TElPKCS7EncryptedContent* EncryptedContent = {read=FEncryptedContent};
	__property Sbcustomcertstorage::TElMemoryCertStorage* Certificates = {read=FCertStorage};
	__property int SignerCount = {read=GetSignerCount, nodefault};
};


class DELPHICLASS TElPKCS7AuthenticatedData;
class PASCALIMPLEMENTATION TElPKCS7AuthenticatedData : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FVersion;
	Sbcustomcertstorage::TElCustomCertStorage* FOriginatorCerts;
	Sbtypes::ByteArray FMacAlgorithm;
	Sbtypes::ByteArray FMacAlgorithmParams;
	Sbtypes::ByteArray FDigestAlgorithm;
	Sbtypes::ByteArray FDigestAlgorithmParams;
	Sbtypes::ByteArray FContentType;
	Classes::TList* FContentParts;
	Sbpkcs7utils::TElPKCS7Attributes* FAuthenticatedAttributes;
	Sbpkcs7utils::TElPKCS7Attributes* FUnauthenticatedAttributes;
	Sbtypes::ByteArray FMac;
	Classes::TList* FRecipientList;
	Sbtypes::ByteArray FAuthenticatedAttributesPlain;
	void __fastcall SetMacAlgorithm(const Sbtypes::ByteArray V);
	void __fastcall SetMacAlgorithmParams(const Sbtypes::ByteArray V);
	void __fastcall SetDigestAlgorithm(const Sbtypes::ByteArray V);
	void __fastcall SetDigestAlgorithmParams(const Sbtypes::ByteArray V);
	void __fastcall SetContentType(const Sbtypes::ByteArray V);
	void __fastcall SetMac(const Sbtypes::ByteArray V);
	int __fastcall GetRecipientCount(void);
	Sbtypes::ByteArray __fastcall GetAuthenticatedAttributesPlain(void);
	int __fastcall AddContentPart(Sbasn1tree::TElASN1DataSource* DataSource)/* overload */;
	int __fastcall AddContentPart(const Sbtypes::ByteArray Value)/* overload */;
	int __fastcall AddContentPart(void * Buffer, int Size)/* overload */;
	void __fastcall ClearContentParts(void);
	int __fastcall GetContentPartCount(void);
	Sbtypes::ByteArray __fastcall GetContent(void);
	void __fastcall SetContent(const Sbtypes::ByteArray Value);
	Sbasn1tree::TElASN1DataSource* __fastcall GetDataSource(void);
	TElPKCS7Recipient* __fastcall GetRecipient(int Index);
	Sbasn1tree::TElASN1DataSource* __fastcall GetContentPart(int Index);
	
public:
	__fastcall TElPKCS7AuthenticatedData(void);
	__fastcall virtual ~TElPKCS7AuthenticatedData(void);
	int __fastcall AddRecipient(void);
	bool __fastcall RemoveRecipient(int Index);
	void __fastcall RecalculateAuthenticatedAttributes(void);
	__property int Version = {read=FVersion, write=FVersion, nodefault};
	__property Sbcustomcertstorage::TElCustomCertStorage* OriginatorCerts = {read=FOriginatorCerts};
	__property TElPKCS7Recipient* Recipients[int Index] = {read=GetRecipient};
	__property Sbasn1tree::TElASN1DataSource* ContentParts[int Index] = {read=GetContentPart};
	__property int RecipientCount = {read=GetRecipientCount, nodefault};
	__property Sbtypes::ByteArray MacAlgorithm = {read=FMacAlgorithm, write=SetMacAlgorithm};
	__property Sbtypes::ByteArray DigestAlgorithm = {read=FDigestAlgorithm, write=SetDigestAlgorithm};
	__property Sbtypes::ByteArray ContentType = {read=FContentType, write=SetContentType};
	__property Sbtypes::ByteArray Content = {read=GetContent, write=SetContent};
	__property Sbpkcs7utils::TElPKCS7Attributes* AuthenticatedAttributes = {read=FAuthenticatedAttributes};
	__property Sbpkcs7utils::TElPKCS7Attributes* UnauthenticatedAttributes = {read=FUnauthenticatedAttributes};
	__property Sbtypes::ByteArray Mac = {read=FMac, write=SetMac};
	__property Sbtypes::ByteArray AuthenticatedAttributesPlain = {read=GetAuthenticatedAttributesPlain};
	__property int ContentPartCount = {read=GetContentPartCount, nodefault};
	__property Sbasn1tree::TElASN1DataSource* DataSource = {read=GetDataSource};
};


class DELPHICLASS TElPKCS7TimestampAndCRL;
class PASCALIMPLEMENTATION TElPKCS7TimestampAndCRL : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	Sbtypes::ByteArray FEncodedTimestamp;
	Sbtypes::ByteArray FEncodedCRL;
	Sbtypes::ByteArray FEncodedValue;
	void __fastcall SetEncodedTimestamp(const Sbtypes::ByteArray V);
	void __fastcall SetEncodedCRL(const Sbtypes::ByteArray V);
	void __fastcall SetEncodedValue(const Sbtypes::ByteArray V);
	__fastcall TElPKCS7TimestampAndCRL(void);
	__fastcall virtual ~TElPKCS7TimestampAndCRL(void);
	__property Sbtypes::ByteArray EncodedTimestamp = {read=FEncodedTimestamp, write=SetEncodedTimestamp};
	__property Sbtypes::ByteArray EncodedCRL = {read=FEncodedCRL, write=SetEncodedCRL};
	__property Sbtypes::ByteArray EncodedValue = {read=FEncodedValue, write=SetEncodedValue};
};


class DELPHICLASS TElPKCS7TimestampedData;
class PASCALIMPLEMENTATION TElPKCS7TimestampedData : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbtypes::ByteArray FContentType;
	Sbtypes::ByteArray FDataURI;
	bool FHashProtected;
	Sbtypes::ByteArray FFileName;
	Sbtypes::ByteArray FMediaType;
	bool FMetaDataAvailable;
	Classes::TList* FTimestamps;
	Classes::TList* FContentParts;
	void __fastcall SetDataURI(const Sbtypes::ByteArray V);
	void __fastcall SetFileName(const Sbtypes::ByteArray V);
	void __fastcall SetMediaType(const Sbtypes::ByteArray V);
	int __fastcall GetTimestampCount(void);
	int __fastcall AddContentPart(Sbasn1tree::TElASN1DataSource* DataSource)/* overload */;
	int __fastcall AddContentPart(const Sbtypes::ByteArray Value)/* overload */;
	int __fastcall AddContentPart(void * Buffer, int Size)/* overload */;
	void __fastcall ClearContentParts(void);
	int __fastcall GetContentPartCount(void);
	Sbtypes::ByteArray __fastcall GetContent(void);
	void __fastcall SetContent(const Sbtypes::ByteArray Value);
	Sbasn1tree::TElASN1DataSource* __fastcall GetDataSource(void);
	TElPKCS7TimestampAndCRL* __fastcall GetTimestamps(int Index);
	Sbasn1tree::TElASN1DataSource* __fastcall GetContentPart(int Index);
	
public:
	__fastcall TElPKCS7TimestampedData(void);
	__fastcall virtual ~TElPKCS7TimestampedData(void);
	int __fastcall AddTimestamp(void);
	bool __fastcall RemoveTimestamp(int Index);
	void __fastcall ClearTimestamps(void);
	Sbtypes::ByteArray __fastcall WriteMetadata(void);
	Sbtypes::ByteArray __fastcall WriteTimestampAndCRL(TElPKCS7TimestampAndCRL* Ts);
	__property Sbtypes::ByteArray DataURI = {read=FDataURI, write=SetDataURI};
	__property bool HashProtected = {read=FHashProtected, write=FHashProtected, nodefault};
	__property Sbtypes::ByteArray FileName = {read=FFileName, write=SetFileName};
	__property Sbtypes::ByteArray MediaType = {read=FMediaType, write=SetMediaType};
	__property bool MetaDataAvailable = {read=FMetaDataAvailable, write=FMetaDataAvailable, nodefault};
	__property TElPKCS7TimestampAndCRL* Timestamps[int Index] = {read=GetTimestamps};
	__property int TimestampCount = {read=GetTimestampCount, nodefault};
	__property Sbtypes::ByteArray Content = {read=GetContent, write=SetContent};
	__property Sbasn1tree::TElASN1DataSource* ContentParts[int Index] = {read=GetContentPart};
	__property int ContentPartCount = {read=GetContentPartCount, nodefault};
	__property Sbasn1tree::TElASN1DataSource* DataSource = {read=GetDataSource};
};


class PASCALIMPLEMENTATION TElPKCS7Message : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbasn1tree::TElASN1ConstrainedTag* FMessage;
	TSBPKCS7ContentType FContentType;
	Sbtypes::ByteArray FData;
	bool FUseImplicitContent;
	bool FUseUndefSize;
	TElPKCS7EnvelopedData* FEnvelopedData;
	TElPKCS7CompressedData* FCompressedData;
	TElPKCS7SignedData* FSignedData;
	TElPKCS7DigestedData* FDigestedData;
	TElPKCS7EncryptedData* FEncryptedData;
	TElPKCS7SignedAndEnvelopedData* FSignedAndEnvelopedData;
	TElPKCS7AuthenticatedData* FAuthenticatedData;
	TElPKCS7TimestampedData* FTimestampedData;
	bool FNoOuterContentInfo;
	bool FAllowUnknownContentTypes;
	Sbtypes::ByteArray FCustomContentType;
	
protected:
	int __fastcall ProcessMessage(void);
	virtual int __fastcall ProcessData(Sbasn1tree::TElASN1CustomTag* Tag);
	virtual int __fastcall ProcessUnknownData(Sbasn1tree::TElASN1CustomTag* Tag);
	virtual int __fastcall ProcessSignedData(Sbasn1tree::TElASN1CustomTag* Tag);
	virtual int __fastcall ProcessEnvelopedData(Sbasn1tree::TElASN1CustomTag* Tag);
	virtual int __fastcall ProcessCompressedData(Sbasn1tree::TElASN1CustomTag* Tag);
	virtual int __fastcall ProcessSignedEnvelopedData(Sbasn1tree::TElASN1CustomTag* Tag);
	virtual int __fastcall ProcessDigestData(Sbasn1tree::TElASN1CustomTag* Tag);
	virtual int __fastcall ProcessEncryptedData(Sbasn1tree::TElASN1CustomTag* Tag);
	virtual int __fastcall ProcessAuthenticatedData(Sbasn1tree::TElASN1CustomTag* Tag);
	virtual int __fastcall ProcessTimestampedData(Sbasn1tree::TElASN1CustomTag* Tag);
	int __fastcall ProcessRecipientInfos(Sbasn1tree::TElASN1CustomTag* Tag, Classes::TList* RecipientList);
	virtual int __fastcall ProcessRecipientInfo(Sbasn1tree::TElASN1CustomTag* Tag, TElPKCS7Recipient* Recipient);
	int __fastcall ProcessEncryptedContentInfo(Sbasn1tree::TElASN1ConstrainedTag* Tag, TElPKCS7EncryptedContent* EncryptedContent);
	void __fastcall ProcessCertificates(Sbasn1tree::TElASN1ConstrainedTag* Tag, Sbcustomcertstorage::TElCustomCertStorage* Storage);
	void __fastcall ProcessCRLs(Sbasn1tree::TElASN1ConstrainedTag* Tag, Sbcrlstorage::TElMemoryCRLStorage* Storage, Sbocspstorage::TElOCSPResponseStorage* OcspStorage);
	int __fastcall ProcessSignerInfos(Sbasn1tree::TElASN1CustomTag* Tag, Classes::TList* SignerList);
	void __fastcall Clear(void);
	void __fastcall SaveEnvelopedData(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveCompressedData(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveTimestampedData(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveRecipientInfos(Sbasn1tree::TElASN1ConstrainedTag* Tag, Classes::TList* RecipientList);
	void __fastcall SaveRecipientInfo(Sbasn1tree::TElASN1ConstrainedTag* Tag, TElPKCS7Recipient* Recipient);
	void __fastcall SaveEncryptedContentInfo(Sbasn1tree::TElASN1ConstrainedTag* Tag, TElPKCS7EncryptedContent* EncryptedContent);
	void __fastcall SaveSignedData(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveCertificates(Sbcustomcertstorage::TElCustomCertStorage* Storage, Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveCRLs(Sbcrlstorage::TElCustomCRLStorage* Storage, Sbocspstorage::TElOCSPResponseStorage* OcspStorage, Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveSignerInfos(Sbasn1tree::TElASN1ConstrainedTag* Tag, Classes::TList* SignerList);
	void __fastcall SaveDigestedData(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveEncryptedData(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveSignedAndEnvelopedData(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveAuthenticatedData(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveMessage(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SetData(const Sbtypes::ByteArray V);
	void __fastcall SetCustomContentType(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElPKCS7Message(void);
	__fastcall virtual ~TElPKCS7Message(void);
	void __fastcall Reset(void);
	int __fastcall LoadFromBuffer(void * Buffer, int Size);
	bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	int __fastcall LoadFromStream(Classes::TStream* Stream, int Count = 0x0);
	void __fastcall SaveToStream(Classes::TStream* Stream);
	__property TSBPKCS7ContentType ContentType = {read=FContentType, write=FContentType, nodefault};
	__property Sbtypes::ByteArray Data = {read=FData, write=SetData};
	__property TElPKCS7EnvelopedData* EnvelopedData = {read=FEnvelopedData};
	__property TElPKCS7CompressedData* CompressedData = {read=FCompressedData};
	__property TElPKCS7SignedData* SignedData = {read=FSignedData};
	__property TElPKCS7DigestedData* DigestedData = {read=FDigestedData};
	__property TElPKCS7EncryptedData* EncryptedData = {read=FEncryptedData};
	__property TElPKCS7SignedAndEnvelopedData* SignedAndEnvelopedData = {read=FSignedAndEnvelopedData};
	__property TElPKCS7AuthenticatedData* AuthenticatedData = {read=FAuthenticatedData};
	__property TElPKCS7TimestampedData* TimestampedData = {read=FTimestampedData};
	__property bool UseImplicitContent = {read=FUseImplicitContent, write=FUseImplicitContent, nodefault};
	__property bool UseUndefSize = {read=FUseUndefSize, write=FUseUndefSize, nodefault};
	__property bool NoOuterContentInfo = {read=FNoOuterContentInfo, write=FNoOuterContentInfo, nodefault};
	__property bool AllowUnknownContentTypes = {read=FAllowUnknownContentTypes, write=FAllowUnknownContentTypes, nodefault};
	__property Sbtypes::ByteArray CustomContentType = {read=FCustomContentType, write=SetCustomContentType};
};


class DELPHICLASS EElPKCS7Error;
class PASCALIMPLEMENTATION EElPKCS7Error : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPKCS7Error(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPKCS7Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPKCS7Error(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPKCS7Error(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPKCS7Error(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPKCS7Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPKCS7Error(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPKCS7Error(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPKCS7Error(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_DATA;
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_SIGNED_DATA;
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_ENVELOPED_DATA;
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA;
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_DIGESTED_DATA;
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_ENCRYPTED_DATA;
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_AUTHENTICATED_DATA;
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_COMPRESSED_DATA;
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_TIMESTAMPED_DATA;
extern PACKAGE Sbtypes::ByteArray SB_OID_PKCS7_COMPRESSION_ZLIB;
extern PACKAGE void __fastcall RaisePKCS7Error(int ErrorCode);
extern PACKAGE int __fastcall ProcessSignerInfo(Sbasn1tree::TElASN1CustomTag* Tag, TElPKCS7Signer* SignerInfo);
extern PACKAGE int __fastcall ProcessAttributes(Sbasn1tree::TElASN1CustomTag* Tag, Sbpkcs7utils::TElPKCS7Attributes* Attributes);
extern PACKAGE void __fastcall SaveSignerInfo(Sbasn1tree::TElASN1ConstrainedTag* Tag, TElPKCS7Signer* Signer);
extern PACKAGE bool __fastcall ProcessContentInfo(Sbasn1tree::TElASN1ConstrainedTag* Tag, void * Buffer, int &Size, Sbtypes::ByteArray &ContentType)/* overload */;
extern PACKAGE bool __fastcall ProcessContentInfo(Sbasn1tree::TElASN1ConstrainedTag* Tag, System::TObject* PKCS7Data, Sbtypes::ByteArray &ContentType)/* overload */;

}	/* namespace Sbpkcs7 */
using namespace Sbpkcs7;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbpkcs7HPP
