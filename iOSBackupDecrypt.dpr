program iOSBackupDecrypt;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  UnitCode_iOSBackupDecrypt in 'src\UnitCode_iOSBackupDecrypt.pas';

begin
  try
    // 1. Extract the keys with the backup password.
    //TiOSBackupDecryptClient.ExecuteExportManifestToJson('C:\ios-backup\ENC', 'password', 'C:\ios-backup\ENC\Decrypted\decrypt_manifest.json');

    // 2. Extract whatever file you want from it.
    //TiOSBackupDecryptClient.ExecuteDecrypt('C:\ios-backup\ENC\3d\3d0d7e5fb2ce288813306e4d4636395e047a3d28', 'c29tZSBwYXNzd29yZCBnb2VzIGhlcmU=', 'C:\ios-backup\ENC\Decrypted\SMS.db');
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
    end;
  end;

  WriteLn('Press Enter key to exit...');
  ReadLn;
end.
