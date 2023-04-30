unit UnitCode_iOSBackupDecrypt;

interface

uses
  System.Classes, System.SysUtils, System.Generics.Collections,
  HlpPBKDF2_HMACNotBuildInAdapter, HlpSHA1, HlpSHA2_256,
  UnitCode_LibPList, UnitCode_BinaryStreamReader, UnitCode_SQLite3,
  UnitCode_Nullable;

type
  TAESCipherMode = (ECB, CBC);

  TAESDecryptionProvider = class(TObject)
  strict private
    procedure ValidateAndRemovePkcs7Padding(AOutputStream: TStream);
  public
    procedure DecryptStream(AInputStream: TStream; const AKey: TBytes; AMode: TAESCipherMode; AOutputStream: TStream);
    procedure DecryptFile(const AInputFilename: string; const AKey: TBytes; AMode: TAESCipherMode; const AOutputFilename: string);
    function DecryptBuffer(AInputBuffer: TBytes; const AKey: TBytes; AMode: TAESCipherMode): TBytes;
  end;

  TPBKDF2KeyDerivationProvider = class(TObject)
  public
    function GenerateKeyWithSha256(const APassword: string; const ASalt: TBytes; AIterations: Cardinal): TBytes;
    function GenerateKeyWithSha1(const ARoundOneKey: TBytes; const ASalt: TBytes; AIterations: Cardinal): TBytes;
  end;

  TProtectionClassKey = class(TObject)
  strict private
    fCLAS: integer;
    fUUID: TBytes;
    fWRAP: TNullable<integer>;
    fKTYP: TNullable<integer>;
    fWPKY: TBytes;
    fKey: TBytes;
  public
    property CLAS: integer read fCLAS write fCLAS;
    property UUID: TBytes read fUUID write fUUID;
    property WRAP: TNullable<integer> read fWRAP;
    property KTYP: TNullable<integer> read fKTYP;
    property WPKY: TBytes read fWPKY write fWPKY;
    property Key: TBytes read fKey write fKey;
  end;

  TKeyBag = class(TObject)
  strict private
    fAesDecryption: TAESDecryptionProvider;
    fPbkdf2: TPBKDF2KeyDerivationProvider;
    fKeyBagData: TPropertyListNode;
    fTagNames: array of AnsiString;
    fAttributes: TDictionary<AnsiString, TBytes>;
    fKeys: TDictionary<integer, TProtectionClassKey>;
    fTYPE: PInteger;
    fWRAP: PInteger;
    fUUID: TBytes;
    procedure ParseKeyBagData();
    function TagInArray(const ATagName: AnsiString; const ATags: array of AnsiString): boolean;
    procedure ReverseByteOrder(AData: Pointer; ASize: NativeUInt);
    function IncPtr(APtr: Pointer; AOffset: NativeUInt): Pointer;
    procedure DisassembleWrappedKey(const AWrappedKey: TBytes; AParts: TList<UInt64>);
    procedure ProcessUnWrapIteration(const AKey: TBytes; const AFirst, ASecond: UInt64; var ARollingSignature, AUnwrappedKeyPart: UInt64);
    function AssembleFinalKey(const AParts: array of UInt64): TBytes;
    function UnwrapEncryptionKey(const AKey: TBytes; const AWrappedKey: TBytes): TBytes;
  public
    constructor Create(const AKeyBagData: TPropertyListNode);
    destructor Destroy(); override;
    procedure Unlock(const APassword: string);
    function UnwrapEncryptionKeyForProtectionClass(AProtectionClass: integer; const AWrappedKey: TBytes): TBytes;
  end;

  TiOSBackedUpFileData = class(TObject)
  strict private
    fFileId: string;
    fDomain: string;
    fRelativePath: string;
    fPropertyList: TPropertyList;
  public
    constructor Create(const AFileId, ADomain, ARelativePath: string; APropertyList: TPropertyList);
    destructor Destroy; override;
    property FileId: string read fFileId;
    property Domain: string read fDomain;
    property RelativePath: string read fRelativePath;
    property PropertyList: TPropertyList read fPropertyList;
  end;

  TiOSDecryptFileData = class(TObject)
  strict private
    fFileId: string;
    fDomain: string;
    fRelativePath: string;
    fKey: string;
  public
    property FileId: string read fFileId write fFileId;
    property Domain: string read fDomain write fDomain;
    property RelativePath: string read fRelativePath write fRelativePath;
    property Key: string read fKey write fKey;
  end;

  TiOSBackupDecryptClient = class(TObject)
  strict private
    fWorkingPath: string;
    fDecryptedManifestFilename: string;
    fAesDecryption: TAESDecryptionProvider;
    fManifestDb: TSQLiteDatabase;
    fSourceBackupPath: string;
    fSourceBackupPassword: string;
    fKeyBag: TKeyBag;
    fInitialized: boolean;
    fManifestPropList: TPropertyList;
    procedure PerformInitialize();
    procedure TestManifestDbConnection;
    procedure EnsureInitialized();
    function LoadFileDataFromManifest(const ASourceFilename: string): TiOSBackedUpFileData;
    procedure LoadAllFileDataFromManifests(AFiles: TObjectList<TiOSDecryptFileData>);
    function ExtractDecryptionKey(APropertyList: TPropertyList): TBytes;
    procedure ExtractFileInternal(const AFileIdFullPath: string; const AKey: TBytes; const AOutputFilename: string);
  public
    constructor Create; overload;
    constructor Create(const ASourceBackupPath: string); overload;
    constructor Create(const ASourceBackupPath: string; const ASourceBackupPassword: string); overload;
    destructor Destroy(); override;
    procedure ExtractFile(const ASourceFilename: string; const AOutputFilename: string); overload;
    procedure ExtractFile(const AFileId: string; const AKey: TBytes; const AOutputFilename: string); overload;
    procedure ExtractFile(const AFileIdFullPath: string; const AKeyBase64: string; const AOutputFilename: string); overload;
    procedure ExportManifestToJson(const AOutputFilename: string);
    class procedure ExecuteDecrypt(const ASourceBackupPath: string; const ASourceBackupPassword: string; const ASourceFilename: string; const AOutputFilename: string); overload;
    class procedure ExecuteDecrypt(const AFileIdFullPath: string; const AFileKeyBase64: string; const AOutputFilename: string); overload;
    class procedure ExecuteExportManifestToJson(const ASourceBackupPath: string; const ASourceBackupPassword: string; const AOutputFilename: string);
  end;

implementation

uses
  WinApi.Windows, System.IOUtils, System.JSON, System.TypInfo, System.NetEncoding, Neon.Core.Persistence, Neon.Core.Persistence.JSON, Neon.Core.Types,
  ClpCipherUtilities, ClpIBufferedCipher, ClpParameterUtilities, ClpParametersWithIV, ClpIKeyParameter, ClpICipherParameters,
  UnitCode_BitConverter;

function GetTempDirectory: string;
begin
  Result := TPath.GetTempFileName;
  TFile.Delete(Result);
  if not ForceDirectories(Result) then
    RaiseLastOSError;
end;

const
  ValidKeySignature: UInt64 = $A6A6A6A6A6A6A6A6;


{ TAESDecryptionProvider }


procedure TAESDecryptionProvider.ValidateAndRemovePkcs7Padding(AOutputStream: TStream);
var
  lPadLength: byte;
  lPadBytes: TBytes;
  b: byte;
begin
  if (AOutputStream.Size > 1) then
  begin
    AOutputStream.Position := AOutputStream.Size - 1;
    AOutputStream.ReadData(lPadLength);
    if ((lPadLength > 0) and (lPadLength <= 16) and (lPadLength < AOutputStream.Size)) then
    begin
      AOutputStream.Position := AOutputStream.Size - lPadLength;
      SetLength(lPadBytes, lPadLength);
      if (AOutputStream.Read(lPadBytes, 0, lPadLength) <> lPadLength) then
      begin
        raise Exception.Create('Failed to read padding.');
      end;
      for b in lPadBytes do
      begin
        if b <> lPadLength then
        begin
          raise Exception.Create('Padding is invalid.');
        end;
      end;
      AOutputStream.Position := AOutputStream.Size - lPadLength - 1;
      AOutputStream.Size := AOutputStream.Size - lPadLength;
    end;
  end;
end;

procedure TAESDecryptionProvider.DecryptStream(AInputStream: TStream; const AKey: TBytes; AMode: TAESCipherMode; AOutputStream: TStream);
var
  lCipher: IBufferedCipher;
  lKeyParam: IKeyParameter;
  lParams: ICipherParameters;
  IV: TBytes;
begin
  AOutputStream.Size := AInputStream.Size;

  case AMode of
    ECB:
    begin
      lCipher := TCipherUtilities.GetCipher('AES/ECB/NOPADDING');
      lParams := TParameterUtilities.CreateKeyParameter('AES', AKey);
    end;
    CBC:
    begin
      lCipher := TCipherUtilities.GetCipher('AES/CBC/NOPADDING');
      SetLength(IV, 16);
      lKeyParam := TParameterUtilities.CreateKeyParameter('AES', AKey);
      lParams := TParametersWithIV.Create(lKeyParam, IV);
      SetLength(IV, 0);
    end
    else
    begin
      raise Exception.Create('Unsupported AES cipher mode.');
    end;
  end;

  lCipher.Init(False, lParams);
  lCipher.ProcessStream(AInputStream, AOutputStream, AInputStream.Size);

  if (AMode = CBC) then
  begin
    ValidateAndRemovePkcs7Padding(AOutputStream);
  end;
end;

procedure TAESDecryptionProvider.DecryptFile(const AInputFilename: string; const AKey: TBytes; AMode: TAESCipherMode; const AOutputFilename: string);
var
  lInputStream: TStream;
  lOutputStream: TStream;
begin
  lOutputStream := TFileStream.Create(AOutputFilename, fmCreate or fmOpenReadWrite or fmShareDenyWrite);
  try
    lInputStream := TFileStream.Create(AInputFilename, fmOpenRead or fmShareDenyWrite);
    try
      DecryptStream(lInputStream, AKey, AMode, lOutputStream);
    finally
      FreeAndNil(lInputStream);
    end;
  finally
    FreeAndNil(lOutputStream);
  end;
end;

function TAESDecryptionProvider.DecryptBuffer(AInputBuffer: TBytes; const AKey: TBytes; AMode: TAESCipherMode): TBytes;
var
  lInputStream: TStream;
  lOutputStream: TStream;
begin
  lOutputStream := TMemoryStream.Create();
  try
    lInputStream := TMemoryStream.Create();
    try
      lInputStream.Write(AInputBuffer, 0, Length(AInputBuffer));
      lInputStream.Position := 0;
      lOutputStream.Size := lInputStream.Size;
      DecryptStream(lInputStream, AKey, AMode, lOutputStream);
      SetLength(Result, lOutputStream.Size);
      lOutputStream.Position := 0;
      lOutputStream.Read(Result, 0, Length(Result));
    finally
      FreeAndNil(lInputStream);
    end;
  finally
    FreeAndNil(lInputStream);
  end;
end;

{ TPBKDF2KeyDerivationProvider }

function TPBKDF2KeyDerivationProvider.GenerateKeyWithSha256(const APassword: string; const ASalt: TBytes; AIterations: Cardinal): TBytes;
var
  lPasswordBytes: TBytes;
  lKdf: TPBKDF2_HMACNotBuildInAdapter;
begin
  lPasswordBytes := TEncoding.ASCII.GetBytes(APassword);
  lKdf := TPBKDF2_HMACNotBuildInAdapter.Create(TSHA2_256.Create(), lPasswordBytes, ASalt, AIterations);
  try
    Result := lKdf.GetBytes(32);
  finally
    lKdf.Free;
  end;
end;

function TPBKDF2KeyDerivationProvider.GenerateKeyWithSha1(const ARoundOneKey: TBytes; const ASalt: TBytes; AIterations: Cardinal): TBytes;
var
  lKdf: TPBKDF2_HMACNotBuildInAdapter;
begin
  lKdf := TPBKDF2_HMACNotBuildInAdapter.Create(TSHA1.Create(), ARoundOneKey, ASalt, AIterations);
  try
    Result := lKdf.GetBytes(32);
  finally
    lKdf.Free;
  end;
end;

{ TKeyBag }

procedure TKeyBag.ParseKeyBagData();
var
  lStream: TStream;
  lReader: TBinaryStreamReader;
  lTagName: AnsiString;
  lLength: integer;
  lData: TBytes;
  lDataAsInt: integer;
  lCurrentKey: TProtectionClassKey;
begin
  lStream := TMemoryStream.Create;
  try
    fKeyBagData.AsData.GetData(lStream);
    lReader := TBinaryStreamReader.Create(lStream, false);
    try
      lCurrentKey := nil;
      while(lStream.Position < lStream.Size) do
      begin
        lTagName := lReader.ReadString(4);
        llength := lReader.ReadInteger(Reversed);
        if lLength > 0 then
          lData := lReader.ReadBytes(llength)
        else
          lData := nil;
        if llength = 4 then
        begin
          lDataAsInt := TBitConverter.ToInt32(lData, 0);
          ReverseByteOrder(@lDataAsInt, SizeOf(Int32));
        end else
        begin
          lDataAsInt := -1;
        end;

        if lTagName = 'TYPE' then
        begin
          if lDataAsInt > 3 then
            raise Exception.Create('Unexpected KeyBag Type: ' + IntToStr(lDataAsInt));
          GetMem(fType, 4);
          fType^ := lDataAsInt;
        end else
        if (lTagName = 'UUID') and (Length(fUUID) = 0) then
        begin
          fUUID := lData;
        end else
        if (lTagName = 'WRAP') and (fWRAP = nil) then
        begin
          GetMem(fWRAP, 4);
          fWRAP^ := lDataAsInt;
        end else
        if lTagName = 'UUID' then
        begin
          if lCurrentKey <> nil then
          begin
            fKeys.Add(lCurrentKey.CLAS, lCurrentKey);
          end;
          lCurrentKey := TProtectionClassKey.Create;
          lCurrentKey.UUID := lData;
        end else
        if TagInArray(lTagName, fTagNames) and (lCurrentKey <> nil) then
        begin
          if lTagName = 'CLAS' then
          begin
            lCurrentKey.CLAS := lDataAsInt;
          end else
          if lTagName = 'KTYP' then
          begin
            lCurrentKey.KTYP.Value := lDataAsInt;
          end else
          if lTagName = 'WRAP' then
          begin
            lCurrentKey.WRAP.Value := lDataAsInt;
          end else
          if lTagName = 'WPKY' then
          begin
            lCurrentKey.WPKY := lData;
          end;
        end else
        begin
          fAttributes.Add(lTagName, lData);
        end;
      end;

      if lCurrentKey <> nil then
      begin
        fKeys.Add(lCurrentKey.CLAS, lCurrentKey);
      end;

      fAttributes.TrimExcess;
      fKeys.TrimExcess;
    finally
      lReader.Free;
    end;
  finally
    lStream.Free;
  end;
end;

function TKeyBag.TagInArray(const ATagName: AnsiString; const ATags: array of AnsiString): boolean;
var
  lTag: AnsiString;
begin
  for lTag in ATags do
  begin
    if lTag = ATagName then
    begin
      Result := True;
      Exit;
    end;
  end;

  Result := False;
end;

function TKeyBag.IncPtr(APtr: Pointer; AOffset: NativeUInt): Pointer;
begin
  Result := Pointer(NativeUInt(APtr) + AOffset);
end;

procedure TKeyBag.ReverseByteOrder(AData: Pointer; ASize: NativeUInt);
var
  I: NativeUInt;
  J: NativeUInt;
  lTemp: Pointer;
begin
  if ASize < 1 then
    Exit;
  lTemp := AllocMem(ASize);
  try
    CopyMemory(lTemp, AData, ASize);
    J := ASize;
    for I := 0 to ASize-1 do
    begin
      Dec(J);
      CopyMemory(IncPtr(AData, I), IncPtr(lTemp, J), 1);
    end;
  finally
    FreeMem(lTemp);
  end;
end;

procedure TKeyBag.DisassembleWrappedKey(const AWrappedKey: TBytes; AParts: TList<UInt64>);
var
  I: integer;
  lStream: TStream;
  lReader: TBinaryStreamReader;
begin
  lStream := TMemoryStream.Create;
  try
    lStream.Write(AWrappedKey, 0, Length(AWrappedKey));
    lStream.Position := 0;
    lReader := TBinaryStreamReader.Create(lStream, False);
    try
      for I := 1 to ((Length(AWrappedKey) div SizeOf(UInt64))) do
      begin
        AParts.Add(lReader.ReadUInt64(Reversed));
      end;
    finally
      lReader.Free;
    end;
  finally
    lStream.Free;
  end;
end;

procedure TKeyBag.ProcessUnWrapIteration(const AKey: TBytes; const AFirst, ASecond: UInt64; var ARollingSignature, AUnwrappedKeyPart: UInt64);
var
  lStream: TStream;
  lReader: TBinaryStreamReader;
  lTempBytes: TBytes;
  lDecryptedChunk: TBytes;
begin
  lStream := TMemoryStream.Create;
  try
    lTempBytes := TBitConverter.GetBytes(AFirst);
    lStream.Write(lTempBytes, 0, Length(lTempBytes));
    lTempBytes := TBitConverter.GetBytes(ASecond);
    lStream.Write(lTempBytes, 0, Length(lTempBytes));
    SetLength(lTempBytes, lStream.Size);
    lStream.Position := 0;
    lStream.Read(lTempBytes, 0, Length(lTempBytes));
    lDecryptedChunk := fAesDecryption.DecryptBuffer(lTempBytes, AKey, ECB);
    lReader := TBinaryStreamReader.Create(lStream, False);
    try
      lStream.Position := 0;
      lStream.Write(lDecryptedChunk, 0, Length(lDecryptedChunk));
      lStream.Position := 0;
      ARollingSignature := lReader.ReadUInt64(Reversed);
      AUnwrappedKeyPart := lReader.ReadUInt64(Reversed);
    finally
      lReader.Free;
    end;
  finally
    lStream.Free;
  end;
end;

function TKeyBag.AssembleFinalKey(const AParts: array of UInt64): TBytes;
var
  I: integer;
  lStream: TStream;
  lTempBytes: TBytes;
begin
  lStream := TMemoryStream.Create;
  try
    for I := 1 to 4 do
    begin
      ReverseByteOrder(@AParts[I], SizeOf(UInt64));
      lTempBytes := TBitConverter.GetBytes(AParts[I]);
      lStream.Write(lTempBytes, 0, Length(lTempBytes));
    end;
    SetLength(Result, SizeOf(UInt64) * 4);
    lStream.Position := 0;
    lStream.Read(Result, 0, Length(Result));
  finally
    lStream.Free;
  end;
end;

function TKeyBag.UnwrapEncryptionKey(const AKey: TBytes; const AWrappedKey: TBytes): TBytes;
var
  I: integer;
  J: integer;
  lPartCount: integer;
  lWrappedKeyParts: TList<UInt64>;
  lUnWrappedKeyParts: array of UInt64;
  lRollingSignature: UInt64;
  lFirst: UInt64;
  lSecond: UInt64;
begin
  lWrappedKeyParts := TList<UInt64>.Create;
  DisassembleWrappedKey(AWrappedKey, lWrappedKeyParts);

  lPartCount := lWrappedKeyParts.Count - 1;
  SetLength(lUnWrappedKeyParts, lPartCount + 1);
  lRollingSignature := lWrappedKeyParts[0];
  for I := 1 to lPartCount do
  begin
    lUnWrappedKeyParts[I] := lWrappedKeyParts[I];
  end;

  for J := 5 downto 0 do
  begin
    for I := lPartCount downto 1 do
    begin
      lFirst := lRollingSignature xor (lPartCount * J + I);
      ReverseByteOrder(@lFirst, SizeOf(UInt64));
      lSecond := lUnWrappedKeyParts[I];
      ReverseByteOrder(@lSecond, SizeOf(UInt64));
      ProcessUnWrapIteration(AKey, lFirst, lSecond, lRollingSignature, lUnWrappedKeyParts[I]);
    end;
  end;

  if lRollingSignature <> ValidKeySignature then
  begin
    Result := nil;
    Exit;
  end;

  Result := AssembleFinalKey(lUnWrappedKeyParts);
end;

constructor TKeyBag.Create(const AKeyBagData: TPropertyListNode);
begin
  fKeyBagData := AKeyBagData;
  fAesDecryption := TAESDecryptionProvider.Create;
  fPbkdf2 := TPBKDF2KeyDerivationProvider.Create;
  SetLength(fTagNames, 4);
  fTagNames[0] := 'WRAP';
  fTagNames[1] := 'CLAS';
  fTagNames[2] := 'KTYP';
  fTagNames[3] := 'WPKY';
  fAttributes := TDictionary<AnsiString, TBytes>.Create;
  fKeys := TDictionary<integer, TProtectionClassKey>.Create;
  ParseKeyBagData;
end;

destructor TKeyBag.Destroy();
begin
  FreeAndNil(fAttributes);
  FreeAndNil(fKeys);
  FreeAndNil(fAesDecryption);
  FreeAndNil(fPbkdf2);
  fKeyBagData := nil;
  inherited;
end;

procedure TKeyBag.Unlock(const APassword: string);
var
  lIterationsRound1: UInt32;
  lIterationsRound2: UInt32;
  lRound1Key: TBytes;
  lRound2Key: TBytes;
  lProtectionClass: TProtectionClassKey;
  lRealKey: TBytes;
begin
  lIterationsRound1 := TBitConverter.ToUInt32(fAttributes['DPIC'], 0);
  ReverseByteOrder(@lIterationsRound1, SizeOf(UInt32));
  lRound1Key := fPbkdf2.GenerateKeyWithSha256(APassword, fAttributes['DPSL'], lIterationsRound1);
  lIterationsRound2 := TBitConverter.ToUInt32(fAttributes['ITER'], 0);
  ReverseByteOrder(@lIterationsRound2, SizeOf(UInt32));
  lRound2Key := fPbkdf2.GenerateKeyWithSha1(lRound1Key, fAttributes['SALT'], lIterationsRound2);

  for lProtectionClass in fKeys.Values do
  begin
    if lProtectionClass.WPKY = nil then
      Continue;
    if (lProtectionClass.WRAP.HasValue) and (lProtectionClass.WRAP.Value = 2) then
    begin
      lRealKey := UnwrapEncryptionKey(lRound2Key, lProtectionClass.WPKY);
      lProtectionClass.Key := lRealKey;
    end;
  end;
end;

function TKeyBag.UnwrapEncryptionKeyForProtectionClass(AProtectionClass: integer; const AWrappedKey: TBytes): TBytes;
var
  lProtectionClassKey: TBytes;
begin
  lProtectionClassKey := fKeys[AProtectionClass].Key;
  Result := UnwrapEncryptionKey(lProtectionClassKey, AWrappedKey);
end;

{ TiOSBackedUpFileData }

constructor TiOSBackedUpFileData.Create(const AFileId, ADomain, ARelativePath: string; APropertyList: TPropertyList);
begin
  fFileId := AFileId;
  fDomain := ADomain;
  fRelativePath := ARelativePath;
  fPropertyList := APropertyList;
end;

destructor TiOSBackedUpFileData.Destroy;
begin
  FreeAndNil(fPropertyList);
  inherited;
end;

{ TiOSBackupDecryptClient }

procedure TiOSBackupDecryptClient.PerformInitialize();
var
  lKeyBagData: TPropertyListNode;
  lManifestKeyData: TPropertyListNode;
  lManifestKeyClass: integer;
  lManifestKeyBytes: TBytes;
  lTempStream: TStream;
  lBytesRead: integer;
  lUnwrappedManifestKey: TBytes;  
begin
  fManifestPropList.LoadFromFile(fSourceBackupPath + '\Manifest.plist');
  fManifestPropList.SaveToFileXml(fSourceBackupPath + '\Manifest-xml.plist');
  lKeyBagData := fManifestPropList.AsDictionary.Items['BackupKeyBag'];
  fKeyBag := TKeyBag.Create(lKeyBagData);
  lManifestKeyData := fManifestPropList.AsDictionary.Items['ManifestKey'];
  lTempStream := TMemoryStream.Create;
  try
    lManifestKeyData.AsData.GetData(lTempStream);
    lManifestKeyClass := 0;
    lBytesRead := lTempStream.Read(lManifestKeyClass, SizeOf(integer));
    if (lBytesRead <> SizeOf(lManifestKeyClass)) then
      raise Exception.Create('Failed to read Maifest Key Class');
    SetLength(lManifestKeyBytes, lTempStream.Size - SizeOf(integer));
    lBytesRead := lTempStream.Read(lManifestKeyBytes, 0, Length(lManifestKeyBytes));
    if (lBytesRead <> Length(lManifestKeyBytes)) then
      raise Exception.Create('Failed to read Maifest Key');
  finally
    lTempStream.Free;
  end;
  fKeyBag.Unlock(fSourceBackupPassword);
  lUnwrappedManifestKey := fKeyBag.UnwrapEncryptionKeyForProtectionClass(lManifestKeyClass, lManifestKeyBytes);
  fAesDecryption.DecryptFile(fSourceBackupPath + '\Manifest.db', lUnwrappedManifestKey, CBC, fDecryptedManifestFilename);
  if not TFile.Exists(fDecryptedManifestFilename) then
    raise Exception.Create('Failed to decrypt manifest.');
  TestManifestDbConnection;
end;

procedure TiOSBackupDecryptClient.TestManifestDbConnection;
var
  lRecordCount: integer;
begin 
  fManifestDb.Connect(fDecryptedManifestFilename);
  with (TSQLiteQuery.Create(fManifestDb)) do
  try
    Open('SELECT COUNT(*) FROM FILES');
    try
      lRecordCount := ExecuteScalar;
      WriteLn(IntToStr(lRecordCount) + ' File(s)');
    finally
      Close;
    end;
  finally
    Free;
  end;  
end;

procedure TiOSBackupDecryptClient.EnsureInitialized();
begin
  if not fInitialized then
  begin
    PerformInitialize();
    fInitialized := True;
  end;
end;

function TiOSBackupDecryptClient.LoadFileDataFromManifest(const ASourceFilename: string): TiOSBackedUpFileData;
var
  lFileId: string;
  lDomain: string;
  lRelativePath: string;
  lFilePropList: TPropertyList;
  lPropListRaw: TBytes;
begin
  fManifestDb.Connect(fDecryptedManifestFilename);
  with (TSQLiteQuery.Create(fManifestDb)) do
  try
    Open('SELECT fileID, domain, relativePath, file FROM FILES WHERE relativePath = :path ORDER BY domain, relativePath LIMIT 1');
    try
      ParamValue['path'] := ASourceFilename;
      Execute;
      lPropListRaw := FieldByName['file'].AsBlobArray;
      if Length(lPropListRaw) = 0 then
      begin
        Result := nil;
        Exit;
      end;
      lFileId := FieldByName['fileID'].AsWideString;
      lDomain := FieldByName['domain'].AsWideString;
      lRelativePath := FieldByName['relativePath'].AsWideString;
      lFilePropList := TPropertyList.Create;
      lFilePropList.LoadFromBuffer(lPropListRaw);
      Result := TiOSBackedUpFileData.Create(lFileId, lDomain, lRelativePath, lFilePropList);
    finally
      Close;
    end;
  finally
    Free;
  end;
end;

procedure TiOSBackupDecryptClient.LoadAllFileDataFromManifests(AFiles: TObjectList<TiOSDecryptFileData>);
var
  lFilePropList: TPropertyList;
  lPropListRaw: TBytes;
  lDecryptData: TiOSDecryptFileData;
begin
  fManifestDb.Connect(fDecryptedManifestFilename);
  with (TSQLiteQuery.Create(fManifestDb)) do
  try
    Open('SELECT fileID, domain, relativePath, file FROM FILES ORDER BY domain, relativePath');
    try
      Execute;
      while not EOF do
      begin
        lPropListRaw := FieldByName['file'].AsBlobArray;
        if Length(lPropListRaw) <> 0 then
        begin
          lDecryptData := TiOSDecryptFileData.Create();
          lDecryptData.FileId := FieldByName['fileID'].AsWideString;
          lDecryptData.Domain := FieldByName['domain'].AsWideString;
          lDecryptData.RelativePath := FieldByName['relativePath'].AsWideString;
          lFilePropList := TPropertyList.Create;
          try
            lFilePropList.LoadFromBuffer(lPropListRaw);
            SetLength(lPropListRaw, 0);
            // Compatible with Newtonsoft JSON
            lDecryptData.Key := TBase64Encoding.Base64.EncodeBytesToString(ExtractDecryptionKey(lFilePropList));
          finally
            lFilePropList.Free;
          end;
          AFiles.Add(lDecryptData);
        end;
        Next;
      end;
    finally
      Close;
    end;
  finally
    Free;
  end;
end;

function TiOSBackupDecryptClient.ExtractDecryptionKey(APropertyList: TPropertyList): TBytes;
var
  lTempStream: TStream;
  lObjects: TPropertyListArray;
  lTop: TPropertyListDictionary;
  lItemId: UInt64;
  lFileData: TPropertyListDictionary;
  lProtectionClass: integer;
  lEncryptionKeyId: UInt64;
  lWrappedKeyData: TPropertyListData;
  lWrappedKeyBytes: TBytes;
begin
  lObjects := APropertyList.AsDictionary['$objects'].AsArray;
  lTop := APropertyList.AsDictionary['$top'].AsDictionary;
  lItemId := lTop['root'].AsUniqueIdentifier;
  lFileData := lObjects[lItemId].AsDictionary;
  if not lFileData.KeyExists('EncryptionKey') then
    Exit;
  lProtectionClass := lFileData['ProtectionClass'].AsUnsignedInteger;
  lEncryptionKeyId := lFileData['EncryptionKey'].AsUniqueIdentifier;
  lWrappedKeyData := lObjects[lEncryptionKeyId].AsDictionary['NS.data'].AsData;
  lTempStream := TMemoryStream.Create;
  try
    lWrappedKeyData.GetData(lTempStream);
    SetLength(lWrappedKeyBytes, lTempStream.Size - 4);
    lTempStream.Position := 4;
    lTempStream.Read(lWrappedKeyBytes, 0, Length(lWrappedKeyBytes));
  finally
    lTempStream.Free;
  end;

  Result := fKeyBag.UnwrapEncryptionKeyForProtectionClass(lProtectionClass, lWrappedKeyBytes);
end;

procedure TiOSBackupDecryptClient.ExtractFileInternal(const AFileIdFullPath: string; const AKey: TBytes; const AOutputFilename: string);
begin
  fAesDecryption.DecryptFile(AFileIdFullPath, AKey, CBC, AOutputFilename);
  WriteLn('Saved: ' + AFileIdFullPath + ' --> ' + AOutputFilename);
end;

constructor TiOSBackupDecryptClient.Create;
begin
  fAesDecryption := TAESDecryptionProvider.Create;
end;

constructor TiOSBackupDecryptClient.Create(const ASourceBackupPath: string);
begin
  Create;
  fManifestDb := TSQLiteDatabase.Create;
  fSourceBackupPath := ASourceBackupPath;
end;

constructor TiOSBackupDecryptClient.Create(const ASourceBackupPath: string; const ASourceBackupPassword: string);
begin
  Create(ASourceBackupPath);
  fWorkingPath := GetTempDirectory;
  fDecryptedManifestFilename := fWorkingPath + '\Manifest.db';
  fSourceBackupPassword := ASourceBackupPassword;
  fManifestPropList := TPropertyList.Create;
end;

destructor TiOSBackupDecryptClient.Destroy();
begin
  FreeAndNil(fAesDecryption);
  FreeAndNil(fManifestDb);
  FreeAndNil(fKeyBag);
  FreeAndNil(fManifestPropList);
  if fWorkingPath <> EmptyStr then
    TDirectory.Delete(fWorkingPath, True);
  inherited;
end;

procedure TiOSBackupDecryptClient.ExtractFile(const ASourceFilename: string; const AOutputFilename: string);
var
  lData: TiOSBackedUpFileData;
  lDecryptionKey: TBytes;
begin
  EnsureInitialized;

  lData := LoadFileDataFromManifest(ASourceFilename);
  if lData <> nil then
  try
    lDecryptionKey := ExtractDecryptionKey(lData.PropertyList);
    if Length(lDecryptionKey) = 0 then
    begin
      WriteLn('Unable to extract decryption key.');
      Exit;
    end;
    ExtractFile(lData.FileId, lDecryptionKey, AOutputFilename);
  finally
    lData.Free;
  end;
end;

procedure TiOSBackupDecryptClient.ExtractFile(const AFileId: string; const AKey: TBytes; const AOutputFilename: string);
var
  lSourceFilename: string;
begin
  lSourceFilename := fSourceBackupPath + '\' + AFileId.Substring(0, 2) + '\' + AFileId;
  ExtractFileInternal(lSourceFilename, AKey, AOutputFilename);
end;

procedure TiOSBackupDecryptClient.ExtractFile(const AFileIdFullPath: string; const AKeyBase64: string; const AOutputFilename: string);
begin
  ExtractFileInternal(AFileIdFullPath, TBase64Encoding.Base64.DecodeStringToBytes(AKeyBase64), AOutputFilename);
end;

procedure TiOSBackupDecryptClient.ExportManifestToJson(const AOutputFilename: string);
var
  lItems: TObjectList<TiOSDecryptFileData>;
  lJsonVal: TJSONValue;
  lJson: string;
begin
  EnsureInitialized;
  lItems := TObjectList<TiOSDecryptFileData>.Create(True);
  try
    LoadAllFileDataFromManifests(lItems);
    lJsonVal := TNeon.ObjectToJSON(lItems);
    try
      lJson := TNeon.Print(lJsonVal, True);
      TFile.WriteAllText(AOutputFilename, lJson);
    finally
      lJsonVal.Free;
    end;
  finally
    lItems.Free;
  end;
end;

class procedure TiOSBackupDecryptClient.ExecuteDecrypt(const ASourceBackupPath: string; const ASourceBackupPassword: string; const ASourceFilename: string; const AOutputFilename: string);
begin
  with (TiOSBackupDecryptClient.Create(ASourceBackupPath, ASourceBackupPassword)) do
  try
    ExtractFile(ASourceFilename, AOutputFilename);
  finally
    Free;
  end;
end;

class procedure TiOSBackupDecryptClient.ExecuteExportManifestToJson(const ASourceBackupPath: string; const ASourceBackupPassword: string; const AOutputFilename: string);
begin
  with (TiOSBackupDecryptClient.Create(ASourceBackupPath, ASourceBackupPassword)) do
  try
    ExportManifestToJson(AOutputFilename);
  finally
    Free;
  end;
end;

class procedure TiOSBackupDecryptClient.ExecuteDecrypt(const AFileIdFullPath: string; const AFileKeyBase64: string; const AOutputFilename: string);
begin
  with (TiOSBackupDecryptClient.Create) do
  try
    ExtractFile(AFileIdFullPath, AFileKeyBase64, AOutputFilename);
  finally
    Free;
  end;
end;

end.
