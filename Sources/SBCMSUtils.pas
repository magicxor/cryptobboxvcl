(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCMSUtils;

interface

uses
  SBCustomCertStorage, 
  SBX509, 
  SBTypes,
  SBUtils;



type
  TSBCMSCertificateNeededEvent = procedure(Sender: TObject;
    Lookup : TElCertificateLookup; var Cert : TElX509Certificate) of object;

implementation

end.
