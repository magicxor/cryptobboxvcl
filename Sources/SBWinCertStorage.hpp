// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbwincertstorage.pas' rev: 21.00

#ifndef SbwincertstorageHPP
#define SbwincertstorageHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbwincrypt.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbalgorithmidentifier.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbrsa.hpp>	// Pascal unit
#include <Sbmskeyblob.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbwincertstorage
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBStorageType { stSystem, stRegistry, stLDAP, stMemory };
#pragma option pop

#pragma option push -b-
enum TSBStorageAccessType { atCurrentService, atCurrentUser, atCurrentUserGroupPolicy, atLocalMachine, atLocalMachineEnterprise, atLocalMachineGroupPolicy, atServices, atUsers };
#pragma option pop

#pragma option push -b-
enum TSBStorageProviderType { ptDefault, ptBaseDSSDH, ptBaseDSS, ptBase, ptRSASchannel, ptRSASignature, ptEnhancedDSSDH, ptEnhancedRSAAES, ptEnhanced, ptBaseSmartCard, ptStrong, ptCryptoProGOST94, ptCryptoProGOST2001 };
#pragma option pop

class DELPHICLASS TElWinCertStorage;
class PASCALIMPLEMENTATION TElWinCertStorage : public Sbcustomcertstorage::TElCustomCertStorage
{
	typedef Sbcustomcertstorage::TElCustomCertStorage inherited;
	
private:
	typedef DynamicArray<void *> _TElWinCertStorage__1;
	
	
private:
	Classes::TStringList* FStores;
	Classes::TStringList* FPhysicalStores;
	TSBStorageType FStorageType;
	TSBStorageAccessType FAccessType;
	TSBStorageProviderType FProvider;
	bool FReadOnly;
	bool FAllowDuplicates;
	Classes::TList* FList;
	Classes::TList* FCtxList;
	Classes::TList* FStoreIndexes;
	_TElWinCertStorage__1 FSystemStoresCtx;
	bool FTryCurrentUser;
	Sbcryptoprov::TElCustomCryptoProvider* FCryptoProvider;
	Sbcryptoprov::TElCustomCryptoProvider* __fastcall GetSuitableCryptoProvider(void);
	__classmethod unsigned __fastcall SetupAccessRights(TSBStorageAccessType Access);
	__classmethod System::UnicodeString __fastcall GetProviderString(TSBStorageProviderType Prov);
	__classmethod unsigned __fastcall GetProviderType(TSBStorageProviderType Prov, int Alg);
	void __fastcall SetPhysicalStores(const Classes::TStringList* Value);
	void __fastcall SetStores(const Classes::TStringList* Value);
	void __fastcall SetStorageType(TSBStorageType Value);
	void __fastcall SetAccessType(TSBStorageAccessType Value);
	
protected:
	void __fastcall Open(void);
	void * __fastcall OpenRegistryStore(const System::UnicodeString Name, unsigned UserRights);
	void * __fastcall OpenLDAPStore(const System::UnicodeString Name, unsigned UserRights);
	void __fastcall ClearInfo(void);
	void __fastcall HandleStoresChange(System::TObject* Sender);
	bool __fastcall LoadPrivateKey(Sbx509::TElX509Certificate* Cert, unsigned Key);
	void __fastcall SetPrivateKeyForCertificate(Sbwincrypt::PCCERT_CONTEXT Context, Sbx509::TElX509Certificate* Cert, bool Exportable = true, bool Protected = true)/* overload */;
	void __fastcall SetPrivateKeyForCertificate(Sbwincrypt::PCCERT_CONTEXT Context, const System::UnicodeString ProvName, const System::UnicodeString ContName, unsigned ProvType, unsigned KeySpec)/* overload */;
	bool __fastcall FindMatchingPrivateKey(Sbx509::TElX509Certificate* Certificate, const System::UnicodeString ProposedContainerName, System::UnicodeString &ContainerName, System::UnicodeString &ProvName, unsigned &ProvType, unsigned &KeySpec);
	void __fastcall InternalAdd(Sbx509::TElX509Certificate* Certificate, const System::UnicodeString StoreName, bool CopyPrivateKey, bool Exportable, bool Protected, bool BindToExistingPrivateKey, const System::UnicodeString PrivateKeyContainerName);
	Sbx509::TElX509Certificate* __fastcall CertContextToSBB(Sbwincrypt::PCCERT_CONTEXT Ctx);
	virtual int __fastcall GetCount(void);
	virtual Sbx509::TElX509Certificate* __fastcall GetCertificates(int Index);
	
public:
	__fastcall virtual TElWinCertStorage(Classes::TComponent* Owner);
	__fastcall virtual ~TElWinCertStorage(void);
	__classmethod void __fastcall GetAvailableStores(Classes::TStrings* Stores, TSBStorageAccessType AccessType = (TSBStorageAccessType)(0x1));
	__classmethod void __fastcall GetAvailablePhysicalStores(const System::UnicodeString SystemStore, Classes::TStrings* Stores, TSBStorageAccessType AccessType = (TSBStorageAccessType)(0x1));
	__classmethod System::UnicodeString __fastcall GetStoreFriendlyName(const System::UnicodeString StoreName);
	virtual void __fastcall Add(Sbx509::TElX509Certificate* Certificate, bool CopyPrivateKey = true)/* overload */;
	HIDESBASE void __fastcall Add(Sbx509::TElX509Certificate* Certificate, const System::UnicodeString StoreName, bool CopyPrivateKey = false, bool Exportable = true, bool Protected = true)/* overload */;
	HIDESBASE void __fastcall Add(Sbx509::TElX509Certificate* Certificate, bool BindToExistingPrivateKey, const System::UnicodeString StoreName, const System::UnicodeString PrivateKeyContainerName)/* overload */;
	virtual void __fastcall Remove(int Index);
	void __fastcall Refresh(void);
	void __fastcall PreloadCertificates(void);
	void __fastcall CreateStore(const System::UnicodeString StoreName);
	void __fastcall DeleteStore(const System::UnicodeString StoreName);
	void __fastcall ListKeyContainers(Classes::TStringList* List)/* overload */;
	void __fastcall ListKeyContainers(Classes::TStringList* List, TSBStorageProviderType ProvType)/* overload */;
	void __fastcall DeleteKeyContainer(const System::UnicodeString ContainerName);
	bool __fastcall Select(HWND Owner, Sbcustomcertstorage::TElCustomCertStorage* SelectedList);
	__classmethod bool __fastcall ImportWizard(HWND Owner);
	__property int Count = {read=GetCount, nodefault};
	__property Sbx509::TElX509Certificate* Certificates[int Index] = {read=GetCertificates};
	__property bool TryCurrentUser = {read=FTryCurrentUser, write=FTryCurrentUser, nodefault};
	
__published:
	__property Classes::TStringList* SystemStores = {read=FStores, write=SetStores};
	__property Classes::TStringList* PhysicalStores = {read=FPhysicalStores, write=SetPhysicalStores};
	__property TSBStorageType StorageType = {read=FStorageType, write=SetStorageType, default=0};
	__property TSBStorageAccessType AccessType = {read=FAccessType, write=SetAccessType, default=1};
	__property TSBStorageProviderType Provider = {read=FProvider, write=FProvider, default=0};
	__property bool ReadOnly = {read=FReadOnly, write=FReadOnly, nodefault};
	__property Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = {read=FCryptoProvider, write=FCryptoProvider};
	__property bool AllowDuplicates = {read=FAllowDuplicates, write=FAllowDuplicates, default=1};
};

typedef TElWinCertStorage ElWinCertStorage
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall Register(void);

}	/* namespace Sbwincertstorage */
using namespace Sbwincertstorage;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbwincertstorageHPP
