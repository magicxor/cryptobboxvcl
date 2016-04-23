unit CertificateGenerationThread;

interface

uses
  Classes,
  SBX509,
  SBX509Ex,
  SBAlgorithmIdentifier,
  SBTypes, 
  SBUtils;

type
  TCertificateGenerationThread = class(TThread)
  private
    FCert : TElX509CertificateEx;
    FCACert : TElX509CertificateEx;
    FKeyAlgorithm : TElAlgorithmIdentifier;
    FSignatureAlgorithm : TElAlgorithmIdentifier;    
    FBits : integer;
  public
    constructor Create(CreateSuspended: Boolean); overload;
    constructor Create(CACert,Cert : TElX509CertificateEx); overload;
    destructor Destroy; override;
    procedure Execute; override;

    property CACert : TElX509CertificateEx read FCACert;
    property Cert : TElX509CertificateEx read FCert;
    property KeyAlgorithm : TElAlgorithmIdentifier read FKeyAlgorithm write FKeyAlgorithm;
    property SignatureAlgorithm : TElAlgorithmIdentifier read FSignatureAlgorithm write FSignatureAlgorithm;
    property Bits : integer read FBits write FBits;
  end;

implementation

constructor TCertificateGenerationThread.Create(CreateSuspended: Boolean);
begin
  inherited Create(CreateSuspended);

  FKeyAlgorithm := nil;
  FSignatureAlgorithm := nil;
end;

destructor TCertificateGenerationThread.Destroy;
begin
  inherited;
end;

procedure TCertificateGenerationThread.Execute;
begin
  if not Assigned(FCACert) then
    FCert.Generate(FKeyAlgorithm, FSignatureAlgorithm, FBits)
  else
    FCert.Generate(FCACert, FKeyAlgorithm, FSignatureAlgorithm, FBits);
end;

constructor TCertificateGenerationThread.Create(CACert, Cert : TElX509CertificateEx);
begin
  inherited Create(true);
  
  Self.FreeOnTerminate := true;
  FCert := Cert;
  FCACert := CACert;
end;

end.
