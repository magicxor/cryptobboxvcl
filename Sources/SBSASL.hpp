// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbsasl.pas' rev: 21.00

#ifndef SbsaslHPP
#define SbsaslHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbhttpsconstants.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbsasl
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBSASLSecurityLevel { saslAuthOnly, saslAuthIntegrity, saslAuthConfidentiality };
#pragma option pop

typedef void __fastcall (__closure *TSBSASLChallengeEvent)(Classes::TStringList* Options);

typedef void __fastcall (__closure *TSBSASLGetValueEvent)(const System::UnicodeString Name, /* out */ System::UnicodeString &Value);

class DELPHICLASS EElSASLError;
class PASCALIMPLEMENTATION EElSASLError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElSASLError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElSASLError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElSASLError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElSASLError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElSASLError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElSASLError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElSASLError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElSASLError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElSASLError(void) { }
	
};


class DELPHICLASS TElSASLClient;
class PASCALIMPLEMENTATION TElSASLClient : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	System::UnicodeString operator[](System::UnicodeString Name) { return Value[Name]; }
	
private:
	Classes::TStringList* FValues;
	TSBSASLChallengeEvent FOnChallenge;
	TSBSASLGetValueEvent FOnGetValue;
	System::UnicodeString __fastcall GetValue(System::UnicodeString Name);
	void __fastcall SetValue(System::UnicodeString Name, const System::UnicodeString NewValue);
	
protected:
	virtual void __fastcall DoChallenge(Classes::TStringList* Options);
	virtual bool __fastcall GetComplete(void) = 0 ;
	virtual System::UnicodeString __fastcall GetMechanismName(void) = 0 ;
	virtual TSBSASLSecurityLevel __fastcall GetSecurityLevel(void);
	virtual bool __fastcall RequestValue(const System::UnicodeString Name, /* out */ System::UnicodeString &OutValue)/* overload */;
	virtual System::UnicodeString __fastcall RequestValue(const System::UnicodeString Name)/* overload */;
	
public:
	__fastcall virtual TElSASLClient(void);
	__fastcall virtual ~TElSASLClient(void);
	virtual void __fastcall ProcessChallenge(const Sbtypes::ByteArray Challenge, /* out */ Sbtypes::ByteArray &Response) = 0 ;
	virtual bool __fastcall ValueExists(const System::UnicodeString Name);
	virtual bool __fastcall WrapData(void * InData, int InSize, void * OutData, int &OutSize)/* overload */;
	virtual bool __fastcall UnwrapData(void * InData, int InSize, void * OutData, int &OutSize)/* overload */;
	virtual bool __fastcall WrapData(const Sbtypes::ByteArray InData, int InStartIndex, int InSize, Sbtypes::ByteArray &OutData, int OutStartIndex, int &OutSize)/* overload */;
	virtual bool __fastcall UnwrapData(const Sbtypes::ByteArray InData, int InStartIndex, int InSize, Sbtypes::ByteArray &OutData, int OutStartIndex, int &OutSize)/* overload */;
	__property bool Complete = {read=GetComplete, nodefault};
	__property System::UnicodeString MechanismName = {read=GetMechanismName};
	__property TSBSASLSecurityLevel SecurityLevel = {read=GetSecurityLevel, nodefault};
	__property System::UnicodeString Value[System::UnicodeString Name] = {read=GetValue, write=SetValue/*, default*/};
	__property TSBSASLChallengeEvent OnChallenge = {read=FOnChallenge, write=FOnChallenge};
	__property TSBSASLGetValueEvent OnGetValue = {read=FOnGetValue, write=FOnGetValue};
};


class DELPHICLASS TElSASLPlainClient;
class PASCALIMPLEMENTATION TElSASLPlainClient : public TElSASLClient
{
	typedef TElSASLClient inherited;
	
private:
	bool FComplete;
	System::UnicodeString __fastcall GetPassword(void);
	System::UnicodeString __fastcall GetUserName(void);
	void __fastcall SetPassword(const System::UnicodeString AValue);
	void __fastcall SetUserName(const System::UnicodeString AValue);
	
protected:
	virtual bool __fastcall GetComplete(void);
	virtual System::UnicodeString __fastcall GetMechanismName(void);
	
public:
	__fastcall virtual TElSASLPlainClient(void);
	virtual void __fastcall ProcessChallenge(const Sbtypes::ByteArray Challenge, /* out */ Sbtypes::ByteArray &Response);
	__property System::UnicodeString Password = {read=GetPassword, write=SetPassword};
	__property System::UnicodeString UserName = {read=GetUserName, write=SetUserName};
public:
	/* TElSASLClient.Destroy */ inline __fastcall virtual ~TElSASLPlainClient(void) { }
	
};


class DELPHICLASS TElSASLLoginClient;
class PASCALIMPLEMENTATION TElSASLLoginClient : public TElSASLClient
{
	typedef TElSASLClient inherited;
	
private:
	int FStep;
	System::UnicodeString __fastcall GetPassword(void);
	System::UnicodeString __fastcall GetUserName(void);
	void __fastcall SetPassword(const System::UnicodeString AValue);
	void __fastcall SetUserName(const System::UnicodeString AValue);
	
protected:
	virtual bool __fastcall GetComplete(void);
	virtual System::UnicodeString __fastcall GetMechanismName(void);
	
public:
	__fastcall virtual TElSASLLoginClient(void);
	virtual void __fastcall ProcessChallenge(const Sbtypes::ByteArray Challenge, /* out */ Sbtypes::ByteArray &Response);
	__property System::UnicodeString Password = {read=GetPassword, write=SetPassword};
	__property System::UnicodeString UserName = {read=GetUserName, write=SetUserName};
public:
	/* TElSASLClient.Destroy */ inline __fastcall virtual ~TElSASLLoginClient(void) { }
	
};


class DELPHICLASS TElSASLCRAMMD5Client;
class PASCALIMPLEMENTATION TElSASLCRAMMD5Client : public TElSASLClient
{
	typedef TElSASLClient inherited;
	
private:
	int FStep;
	System::UnicodeString __fastcall GetPassword(void);
	System::UnicodeString __fastcall GetUserName(void);
	void __fastcall SetPassword(const System::UnicodeString AValue);
	void __fastcall SetUserName(const System::UnicodeString AValue);
	
protected:
	virtual bool __fastcall GetComplete(void);
	virtual System::UnicodeString __fastcall GetMechanismName(void);
	
public:
	__fastcall virtual TElSASLCRAMMD5Client(void);
	virtual void __fastcall ProcessChallenge(const Sbtypes::ByteArray Challenge, /* out */ Sbtypes::ByteArray &Response);
	__property System::UnicodeString Password = {read=GetPassword, write=SetPassword};
	__property System::UnicodeString UserName = {read=GetUserName, write=SetUserName};
public:
	/* TElSASLClient.Destroy */ inline __fastcall virtual ~TElSASLCRAMMD5Client(void) { }
	
};


class DELPHICLASS TElSASLAnonymousClient;
class PASCALIMPLEMENTATION TElSASLAnonymousClient : public TElSASLClient
{
	typedef TElSASLClient inherited;
	
private:
	int FStep;
	System::UnicodeString __fastcall GetAuthID(void);
	void __fastcall SetAuthID(const System::UnicodeString AValue);
	
protected:
	virtual bool __fastcall GetComplete(void);
	virtual System::UnicodeString __fastcall GetMechanismName(void);
	
public:
	__fastcall virtual TElSASLAnonymousClient(void);
	virtual void __fastcall ProcessChallenge(const Sbtypes::ByteArray Challenge, /* out */ Sbtypes::ByteArray &Response);
	__property System::UnicodeString AuthID = {read=GetAuthID, write=SetAuthID};
public:
	/* TElSASLClient.Destroy */ inline __fastcall virtual ~TElSASLAnonymousClient(void) { }
	
};


class DELPHICLASS TElSASLExternalClient;
class PASCALIMPLEMENTATION TElSASLExternalClient : public TElSASLClient
{
	typedef TElSASLClient inherited;
	
private:
	bool FComplete;
	int FStep;
	System::UnicodeString __fastcall GetAuthID(void);
	void __fastcall SetAuthID(const System::UnicodeString AValue);
	
protected:
	virtual bool __fastcall GetComplete(void);
	virtual System::UnicodeString __fastcall GetMechanismName(void);
	
public:
	__fastcall virtual TElSASLExternalClient(void);
	virtual void __fastcall ProcessChallenge(const Sbtypes::ByteArray Challenge, /* out */ Sbtypes::ByteArray &Response);
	__property System::UnicodeString AuthID = {read=GetAuthID, write=SetAuthID};
public:
	/* TElSASLClient.Destroy */ inline __fastcall virtual ~TElSASLExternalClient(void) { }
	
};


class DELPHICLASS TElSASLDigestMD5Client;
class PASCALIMPLEMENTATION TElSASLDigestMD5Client : public TElSASLClient
{
	typedef TElSASLClient inherited;
	
private:
	int FStep;
	bool FMore;
	int FReqMethod;
	System::UnicodeString FSNonce;
	System::UnicodeString FCNonce;
	int FCNonceCount;
	System::UnicodeString FCRequest;
	bool FUUEncodeData;
	Sbtypes::ByteArray FCached;
	Classes::TList* __fastcall ParseParamsLine(const System::UnicodeString Params);
	int __fastcall GetParamsPos(const System::UnicodeString ParamName, Classes::TList* &Params);
	void __fastcall ClearList(Classes::TList* &List);
	System::UnicodeString __fastcall GetPassword(void);
	System::UnicodeString __fastcall GetUserName(void);
	System::UnicodeString __fastcall GetURI(void);
	void __fastcall SetPassword(const System::UnicodeString AValue);
	void __fastcall SetUserName(const System::UnicodeString AValue);
	void __fastcall SetURI(const System::UnicodeString AValue);
	
protected:
	virtual bool __fastcall GetComplete(void);
	virtual System::UnicodeString __fastcall GetMechanismName(void);
	
public:
	__fastcall virtual TElSASLDigestMD5Client(void);
	__fastcall virtual ~TElSASLDigestMD5Client(void);
	virtual void __fastcall ProcessChallenge(const Sbtypes::ByteArray Challenge, /* out */ Sbtypes::ByteArray &Response);
	__property System::UnicodeString Password = {read=GetPassword, write=SetPassword};
	__property System::UnicodeString UserName = {read=GetUserName, write=SetUserName};
	__property System::UnicodeString RequestURI = {read=GetURI, write=SetURI};
	__property int RequestMethod = {read=FReqMethod, write=FReqMethod, nodefault};
	__property System::UnicodeString CustomRequestMethod = {read=FCRequest, write=FCRequest};
};


//-- var, const, procedure ---------------------------------------------------
#define SB_SASL_MECHANISM_PLAIN L"PLAIN"
#define SB_SASL_MECHANISM_LOGIN L"LOGIN"
#define SB_SASL_MECHANISM_CRAM_MD5 L"CRAM-MD5"
#define SB_SASL_MECHANISM_EXTERNAL L"EXTERNAL"
#define SB_SASL_MECHANISM_ANONYMOUS L"ANONYMOUS"
#define SB_SASL_MECHANISM_DIGEST_MD5 L"DIGEST-MD5"
#define SB_SASL_MECHANISM_NTLM L"NTLM"
#define SB_SASL_MECHANISM_GSSAPI L"GSSAPI"
static const Word SB_SASL_ERROR_BASE = 0xba50;
static const Word SB_SASL_CRAM_ERROR_EMPTY_CHALLENGE = 0xba51;
static const Word SB_SASL_CRAM_ERROR_INVALID_CHALLENGE = 0xba52;
static const Word SB_SASL_DIGEST_ERROR_INVALID_CHALLENGE = 0xba53;
static const Word SB_SASL_DIGEST_ERROR_INVALID_REALM = 0xba54;
static const Word SB_SASL_DIGEST_ERROR_PARAMETER_NOT_SPECIFIED = 0xba55;
extern PACKAGE TElSASLClient* __fastcall CreateSASLClient(const System::UnicodeString Mechanism)/* overload */;
extern PACKAGE TElSASLClient* __fastcall CreateSASLClient(const Sbtypes::StringArray Mechanisms)/* overload */;

}	/* namespace Sbsasl */
using namespace Sbsasl;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbsaslHPP
