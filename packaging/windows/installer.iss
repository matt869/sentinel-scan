; Inno Setup script for Sentinel Scan.
;
; Build the PyInstaller bundle first, then compile this:
;
;   pyinstaller packaging/windows/sentinel.spec --clean --noconfirm
;   iscc packaging\windows\installer.iss
;
; Output lands in packaging\windows\Output\.
;
; Pass the version in from CI:
;   iscc /DMyAppVersion=0.4.0 packaging\windows\installer.iss

#ifndef MyAppVersion
  #define MyAppVersion "0.4.0"
#endif

#define MyAppName "Sentinel Scan"
#define MyAppPublisher "matt869"
#define MyAppURL "https://github.com/sentinel-scan/sentinel-scan"
#define MyAppExeName "sentinel-gui.exe"
#define MyAppCliName "sentinel.exe"

[Setup]
; A stable GUID. Changing it turns upgrades into side-by-side installs.
AppId={{7A3E9C41-2B8D-4F6A-9E15-3C7D8B2A4F60}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\Sentinel Scan
DefaultGroupName=Sentinel Scan
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=Output
OutputBaseFilename=sentinel-scan-{#MyAppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Per-machine install so the scanner can read other users' profiles. Users
; who only want their own files can pick a per-user directory.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline dialog
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Add the sentinel command to PATH"; \
    GroupDescription: "Command line"; Flags: checkedonce
Name: "contextmenu"; Description: "Add ""Scan with Sentinel"" to the right-click menu"; \
    GroupDescription: "Shell integration"

[Files]
; The whole PyInstaller output directory.
Source: "..\..\dist\sentinel\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\docs\privacy.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\..\docs\faq.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Privacy statement"; Filename: "{app}\docs\privacy.md"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Tasks: desktopicon

[Registry]
; "Scan with Sentinel" on files and folders.
Root: HKA; Subkey: "Software\Classes\*\shell\SentinelScan"; \
    ValueType: string; ValueName: ""; ValueData: "Scan with Sentinel"; \
    Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\SentinelScan"; \
    ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"; \
    Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\SentinelScan\command"; \
    ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppCliName}"" scan ""%1"""; \
    Flags: uninsdeletekey; Tasks: contextmenu

Root: HKA; Subkey: "Software\Classes\Directory\shell\SentinelScan"; \
    ValueType: string; ValueName: ""; ValueData: "Scan with Sentinel"; \
    Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\SentinelScan\command"; \
    ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppCliName}"" scan ""%1"""; \
    Flags: uninsdeletekey; Tasks: contextmenu

[Run]
Filename: "{app}\{#MyAppCliName}"; Parameters: "update"; \
    Description: "Download the latest signatures"; \
    Flags: postinstall skipifsilent runascurrentuser
Filename: "{app}\{#MyAppExeName}"; \
    Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Logs and caches are ours to clean up. The quarantine vault is NOT removed
; automatically — it may hold the only copy of a file the user wants back,
; and silently destroying it during an uninstall would be indefensible.
Type: filesandordirs; Name: "{localappdata}\sentinel-scan\logs"
Type: filesandordirs; Name: "{localappdata}\sentinel-scan\signatures"

[Code]
const
  EnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

procedure AddToPath();
var
  Existing: string;
begin
  if not RegQueryStringValue(HKLM, EnvironmentKey, 'Path', Existing) then
    Existing := '';
  if Pos(LowerCase(ExpandConstant('{app}')), LowerCase(Existing)) = 0 then
  begin
    if (Existing <> '') and (Existing[Length(Existing)] <> ';') then
      Existing := Existing + ';';
    RegWriteExpandStringValue(HKLM, EnvironmentKey, 'Path',
      Existing + ExpandConstant('{app}'));
  end;
end;

procedure RemoveFromPath();
var
  Existing: string;
  Target: string;
  Position: Integer;
begin
  if not RegQueryStringValue(HKLM, EnvironmentKey, 'Path', Existing) then
    exit;
  Target := ExpandConstant('{app}') + ';';
  Position := Pos(LowerCase(Target), LowerCase(Existing));
  if Position = 0 then
  begin
    Target := ';' + ExpandConstant('{app}');
    Position := Pos(LowerCase(Target), LowerCase(Existing));
  end;
  if Position > 0 then
  begin
    Delete(Existing, Position, Length(Target));
    RegWriteExpandStringValue(HKLM, EnvironmentKey, 'Path', Existing);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToPath();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  VaultPath: string;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RemoveFromPath();

    VaultPath := ExpandConstant('{localappdata}\sentinel-scan\quarantine');
    if DirExists(VaultPath) then
      MsgBox('Quarantined files have been left in place at:' + #13#10 + #13#10 +
             VaultPath + #13#10 + #13#10 +
             'They are stored obfuscated and cannot run. Delete this folder ' +
             'yourself once you are sure you do not need anything from it.',
             mbInformation, MB_OK);
  end;
end;
