unit ExtensionEncoder;

interface
uses Classes, SBTypes, SBStrUtils, SBUtils, SBX509, SBX509Ext, SBRDN, SysUtils;

// Authority Information Access
function GetAuthorityInformationAccess(Ext : TElAuthorityInformationAccessExtension) : string;
// Authority Key Identifier
function GetAuthorityKeyIdentifierValue(Ext : TElAuthorityKeyIdentifierExtension) : string;
// Basic constraint
function GetBasicConstraintValue(Ext : TElBasicConstraintsExtension) : string;
// Certificate policies
function GetCertificatePoliciesValue(Ext : TElCertificatePoliciesExtension) : string;
// Distribution points
function GetDistributionPointValue(Ext : TElCRLDistributionPointsExtension) : string;
// Extended key usage
function GetExtendedKeyUsageValue(Ext : TElExtendedKeyUsageExtension) : string;
// Key usage
function GetKeyUsageValue(Ext : TElKeyUsageExtension) : string;
// Name constraints
function GetNameConstraints(Ext : TElNameConstraintsExtension) : string;
// Issuer alternative name
function GetIssuerAlternativeNameValue(Ext : TElAlternativeNameExtension) : string;
// Netscape certificate type
function GetNetscapeCertType(Ext : TElNetscapeCertTypeExtension) : string;
// Policy constraints
function GetPolicyConstraintsValue(Ext : TElPolicyConstraintsExtension) : string;
// Policies mapping
function GetPoliciesMappingValue(Ext : TElPolicyMappingsExtension) : string;
// Key Usage period
function GetUsagePeriodValue(Ext : TElPrivateKeyUsagePeriodExtension) : string;
// Subject alternative name
function GetSubjectAltNameValue(Ext : TElAlternativeNameExtension) : string;

// Used to format string to it's hex representation
function BuildHexString(St : ByteArray) : string;

implementation
// ------------ Common functions -------------
function AddSt(St,AddSt,Separator : string) : string;
begin
  If St<>'' then Result:=St + Separator + AddSt
    else Result:=AddSt;
  if AddSt = '' then  Result:=St;
  Result:=StringReplace(Result,#13#10#13#10,#13#10,[rfReplaceAll]);
  //St:=StringReplace(St,#13#10#13#10,#13#10,[rfReplaceAll]);
end;

// Used to format string to it's hex representation
function BuildHexString(St : ByteArray) : string;
var i : integer;
begin
  Result:='';
  for I := 0 to Length(St) - 1 do
    Result := Result + IntToHex(St[i], 2) + ' ';
end;

// Get TElRelativeDistinguishedName value
function GetRDNValue(Value : TElRelativeDistinguishedName) : string;
var i : integer;
begin
  Result:='';
  for i:=0 to Value.Count - 1 do
    AddSt(Result,OIDToStr(Value.OIDs[i]) + '=' + BuildHexString(Value.Values[i]),', ');
end;

// Encode general name
function GetGeneralName(TargetSL : TStringList;Name : TElGeneralName;StartTag : string = '') : string;
var SL : TStringList;
procedure AddValue(Key,Value : string);
var ListTag : string;
begin
  if Value = '' then exit;
  ListTag:=StartTag + Key;
  SL.Values[ListTag]:=AddSt(SL.Values[ListTag],Value,', ');
end;
begin
  SL:=TStringList.Create;
  If Assigned(TargetSL) then
    If TargetSL.Count > 0 then SL.Add(TargetSL.Text);
  SL.Sorted:=False;
  with Name do
  case NameType of
    gnRFC822Name : AddValue('RFC822 Name',RFC822Name);
    gnDNSName : AddValue('DNS Name',DNSName);
    gnDirectoryName : AddValue('Directory Name',GetRDNValue(DirectoryName));
    gnEdiPartyName :
    begin
      AddValue('Edi Party Name.Name Assigner',EdiPartyName.NameAssigner);
      AddValue('Edi Party Name.Party Name',EdiPartyName.PartyName);
    end;
    gnUniformResourceIdentifier : AddValue('URI',UniformResourceIdentifier);
    gnIPAddress :  AddValue('IP Address',IPAddress);
    gnRegisteredID : AddValue('Registered ID',BuildHexString(RegisteredID));
    gnOtherName : AddValue('Other Name', OIDToStr(OtherName.OID) + '=' + BuildHexString(OtherName.Value));
    gnUnknown : AddValue('Unknown','Unknown');
  end;
  SL.Sorted:=True;
  Result:=SL.Text;
  SL.Free;
end;

// Encode general names in form DirectoryName=Name1, Name2...
function GetGeneralNames(Names : TElGeneralNames;StartTag : string = '') : string;
var SL : TStringList;
    St : string;
    i : integer;
begin
  SL:=TStringList.Create;
  SL.Sorted:=False;
  for i:=0 to Names.Count - 1 do
  begin
    St:=GetGeneralName(SL,Names.Names[i],StartTag);
    SL.Clear;
    SL.Add(St);
  end;
  i:=SL.Count - 1;
  while (i >= 0) and (i >= SL.Count-1) do
  begin
    if (SL[i] = '') or (SL[i]=#13#10) then SL.Delete(i);
    dec(i);
  end;
  SL.Sorted:=True;
  Result:=SL.Text;
  SL.Free;
end;

function GetNameConstraint(C : TElNameConstraint;StartTag : string = '') : string;
var St : string;
begin
  St:=GetGeneralName(nil,C.Base,StartTag);
  St:=AddSt(St,'Minimum=' + IntToStr(C.Minimum),#13#10);
  St:=AddSt(St,'Maximum=' + IntToStr(C.Maximum),#13#10);
  Result:=St;
end;

// -------------------------------------------

function GetAuthorityInformationAccess(Ext : TElAuthorityInformationAccessExtension) : string;
var I : integer;
    AccessMethod : string;
    SL : TStringList;
    ST : string;
begin
  AccessMethod:='';
  SL:=TStringList.Create;
  SL.Sorted:=False;
  for i:=0 to Ext.Count - 1 do
  begin
    St:=GetGeneralName(SL,Ext.AccessDescriptions[i].AccessLocation,'Access Location.');
    SL.Clear;
    SL.Add(St);
    AccessMethod:=AddSt(AccessMethod,OIDToStr(Ext.AccessDescriptions[i].AccessMethod),', ');
  end;
  If AccessMethod<>'' then SL.Insert(0,'Access Method=' + AccessMethod);
  //SL.Sorted:=True;
  Result:=SL.Text;
end;

function GetAuthorityKeyIdentifierValue(Ext : TElAuthorityKeyIdentifierExtension) : string;
begin
  Result:='';
  if Length(Ext.AuthorityCertSerial) > 0 then
    Result:=AddSt(Result,'Authority Cert Serial=' + BuildHexString(Ext.AuthorityCertSerial),#13#10);
  if Length(Ext.KeyIdentifier) > 0 then
    Result:=AddSt(Result,'Key Identifier=' + BuildHexString(Ext.KeyIdentifier),#13#10);
  Result:=AddSt(Result,GetGeneralNames(Ext.AuthorityCertIssuer,'Authority Cert Issuer.'),#13#10);
end;

function GetBasicConstraintValue(Ext : TElBasicConstraintsExtension) : string;
begin
  if Ext.CA then
    Result:='Subject Type=CA, Path length constraint=' + IntToStr(Ext.PathLenConstraint)
  else Result:='';
end;

function GetCertificatePoliciesValue(Ext : TElCertificatePoliciesExtension) : string;
var i, j, k : integer;
    NumberSt,St : string;
begin
   St:='';
   for i:=0 to Ext.Count - 1 do
     for k:=0 to Ext.PolicyInformation[i].QualifierCount - 1 do
       with Ext.PolicyInformation[i].Qualifiers[k].UserNotice do
       begin
         if (Ext.PolicyInformation[i].Qualifiers[k].CPSURI <> '') then
           St := AddSt(St,'CPS URI=' + Ext.PolicyInformation[i].Qualifiers[k].CPSURI,#13#10);
         St := AddSt(St,'Policy Identifier=' +
               BuildHexString(Ext.PolicyInformation[i].PolicyIdentifier),#13#10);
         If Organization <> '' then
           St := AddSt(St,'Organization=' + Organization,#13#10);
         NumberSt:='';

         for j:=0 to NoticeNumbersCount - 1 do
           NumberSt:=AddSt(NumberSt,Format('%x',[NoticeNumbers[j]]),' ');
         if NumberSt <> '' then
           St:=AddSt(St,'Notice Numbers=' + NumberSt,#13#10);
         St:=AddSt(St,'Explicit Text=' + ExplicitText,#13#10);
       end;
   Result:=St;
end;


function GetDistributionPointValue(Ext : TElCRLDistributionPointsExtension) : string;
var i : integer;
    ReasonSt,St : string;
    DP : TElDistributionPoint;
begin
  St:='';
  for i:=0 to Ext.Count - 1 do
  begin
    DP:=Ext.DistributionPoints[i];
    St:=AddSt(St,
      GetGeneralNames(DP.CRLIssuer,'CRL Issuer.'),'');
    St:=AddSt(St,
      GetGeneralNames(DP.Name,'Name.'),'');
    ReasonSt:='';
    if (rfUnspecified in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'Unspecified',', ');
    if (rfKeyCompromise in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'Key Compromise',', ');
    if (rfCACompromise in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'CA Compromise',', ');
    if (rfAffiliationChanged in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'Affiliation Changed',', ');
    if (rfSuperseded in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'Superseded',', ');
    if (rfCessationOfOperation in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'Cessation Of Operation',', ');
    if (rfCertificateHold in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'Certificate Hold',', ');
    if (rfObsolete1 in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'Obsolete1',', ');
    if (rfRemoveFromCRL in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'Remove From CRL',', ');
    if (rfPrivilegeWithdrawn in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'Privilege Withdrawn',', ');
    if (rfAACompromise in DP.ReasonFlags) then ReasonSt:=AddSt(ReasonSt,'AA Compromise',', ');
    if ReasonSt<>'' then St:=AddSt(St,'Reason=' + ReasonSt,#13#10);
  end;
  Result:=St;
end;


function GetExtendedKeyUsageValue(Ext : TElExtendedKeyUsageExtension) : string;
var i : integer;
begin
  Result:='';
  if Ext.ServerAuthentication then Result:=AddSt(Result,'Server authentication',', ');
  if Ext.ClientAuthentication then Result:=AddSt(Result,'Client authentication',', ');
  if Ext.CodeSigning then Result:=AddSt(Result,'Code signing',', ');
  if Ext.EmailProtection then Result:=AddSt(Result,'E-mail protection',', ');
  if Ext.TimeStamping then Result:=AddSt(Result,'Time stamping',', ');
  Result:=AddSt(Result,'Custom Usage : ' + IntToStr(Ext.CustomUsageCount),', ');
  For i:=0 to Ext.CustomUsageCount - 1 do
    Result:=AddSt(Result,BuildHexString(Ext.CustomUsages[i]),', ');
end;

function GetKeyUsageValue(Ext : TElKeyUsageExtension) : string;
begin
  Result:='';
  if Ext.DigitalSignature then Result:=AddSt(Result,'Digital signature',', ');
  if Ext.NonRepudiation then Result:=AddSt(Result,'Non-repudation',', ');
  if Ext.KeyEncipherment then Result:=AddSt(Result,'Key encipherment',', ');
  if Ext.DataEncipherment then Result:=AddSt(Result,'Data encipherment',', ');
  if Ext.KeyAgreement then Result:=AddSt(Result,'Key agreement',', ');
  if Ext.KeyCertSign then Result:=AddSt(Result,'Certificate signing',', ');
  if Ext.CRLSign then Result:=AddSt(Result,'CRL signing',', ');
  if Ext.EncipherOnly then Result:=AddSt(Result,'Encipher only',', ');
  if Ext.DecipherOnly then Result:=AddSt(Result,'Decipher only',', ');
end;

function GetNameConstraints(Ext : TElNameConstraintsExtension) : string;
var St : string;
    i : integer;
begin
  St:='';
  if Ext.ExcludedCount > 0 then
  begin
    St:=AddSt(St,'Excluded : ',#13#10);
    for i:=0 to Ext.ExcludedCount - 1 do
      St:=AddSt(St,GetNameConstraint(Ext.ExcludedSubtrees[i]),#13#10);
  end;
  if Ext.PermittedCount > 0 then
  begin
    St:=AddSt(St,'Permitted : ',#13#10);
    for i:=0 to Ext.PermittedCount - 1 do
      St:=AddSt(St,GetNameConstraint(Ext.PermittedSubtrees[i]),#13#10);
  end;
  Result:=St;
end;

function GetIssuerAlternativeNameValue(Ext : TElAlternativeNameExtension) : string;
begin
  Result:=GetGeneralNames(Ext.Content);
end;

function GetNetscapeCertType(Ext : TElNetscapeCertTypeExtension) : string;
var CertType : TElNetscapeCertType;
begin
  CertType:=Ext.CertType;
  Result:='';
  if (nsSSLClient in CertType) then Result:=AddSt(Result,'SSL Client',', ');
  if (nsSSLServer in CertType) then Result:=AddSt(Result,'SSL Server',', ');
  if (nsSMIME in CertType) then Result:=AddSt(Result,'S/MIME',', ');
  if (nsObjectSign in CertType) then Result:=AddSt(Result,'Object Signing',', ');
  if (nsSSLCA in CertType) then Result:=AddSt(Result,'SSL CA',', ');
  if (nsSMIMECA in CertType) then Result:=AddSt(Result,'S/MIME CA',', ');
  if (nsObjectSignCA in CertType) then Result:=AddSt(Result,'Object Signing CA',', ');
end;

function GetPolicyConstraintsValue(Ext : TElPolicyConstraintsExtension) : string;
begin
  Result:='Require Explicit Policy=' + IntToStr(Ext.RequireExplicitPolicy) + #13#10 +
   'Inhibit Policy Mapping=' + IntToStr(Ext.InhibitPolicyMapping);
end;


function GetPoliciesMappingValue(Ext : TElPolicyMappingsExtension) : string;
var i : integer;
    IssuerPolicy, SubjectPolicy : string;
begin
  IssuerPolicy:='';
  SubjectPolicy:='';
  for i:=0 to Ext.Count - 1 do
  begin
    AddSt(IssuerPolicy,BuildHexString(Ext.Policies[i].IssuerDomainPolicy),', ');
    AddSt(SubjectPolicy,BuildHexString(Ext.Policies[i].SubjectDomainPolicy),', ');
  end;
  Result:='Issuer Domain Policy=' + IssuerPolicy + #13#10 +
    'Subject Domain Policy=' + SubjectPolicy;
end;

function GetUsagePeriodValue(Ext : TElPrivateKeyUsagePeriodExtension) : string;
begin
  Result:='Not after=' + DateTimeToStr(Ext.NotAfter) + #13#10 +
    'Not before=' + DateTimeToStr(Ext.NotBefore);
end;


function GetSubjectAltNameValue(Ext : TElAlternativeNameExtension) : string;
begin
  Result:=GetGeneralNames(Ext.Content,'');
end;


end.
