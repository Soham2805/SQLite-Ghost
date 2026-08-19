[Setup]
AppName=SQLite-Ghost
AppVersion=0.1.0
AppPublisher=Soham2805
DefaultDirName={autopf}\SQLite-Ghost
DefaultGroupName=SQLite-Ghost
OutputBaseFilename=SQLite-Ghost-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
ChangesEnvironment=yes

[Files]
Source: "dist\sqlite-ghost.exe"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
; This adds the installation directory to the user's PATH environment variable
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]
// Helper function to check if the path is already in the PATH variable
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  // Look for the path with leading and trailing semicolon to prevent duplicate additions
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
