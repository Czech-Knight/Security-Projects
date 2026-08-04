#define MyAppName "YashSec Autopilot"
#define MyAppVersion "1.0.0-rc1"
#define MyAppPublisher "Yash"
#define MyAppExeName "YashSec Autopilot.exe"

[Setup]
AppId={{5D6C6B10-07B7-46EA-BB4C-CE41B4F5BA89}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\YashSec Autopilot
DefaultGroupName=YashSec Autopilot
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir=..\dist\installer
OutputBaseFilename=YashSec-Autopilot-Setup-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\desktop\src-tauri\icons\icon.ico
LicenseFile=..\LICENSE
DisableProgramGroupPage=yes
CloseApplications=yes
RestartApplications=no
ChangesEnvironment=no
VersionInfoVersion=1.0.0.0
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
MinVersion=10.0.19041

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "launchafter"; Description: "Launch YashSec Autopilot after setup"; GroupDescription: "After installation:"; Flags: checkedonce

[Files]
Source: "..\dist\desktop\YashSec Autopilot.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\desktop\YashSecBackend.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\desktop\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\FIRST_RUN_AND_INTENDED_BEHAVIOUR.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\EXTERNAL_TOOLS_INSTALLATION_AND_INTEGRATION_GUIDE.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\OLLAMA_AND_AIRLLM_GUIDE.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\WINDOWS_BUILD_AND_RELEASE_GUIDE.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\OLLAMA_MODES.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\SECURITY_AND_SANITIZATION.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\DEPLOYMENT.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\RELEASE_NOTES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\YashSec Autopilot"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Documentation"; Filename: "{app}\docs"
Name: "{autodesktop}\YashSec Autopilot"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch YashSec Autopilot"; Flags: nowait postinstall skipifsilent; Tasks: launchafter

[UninstallDelete]
; Program files are removed by the uninstaller. User data under LocalAppData is deliberately preserved.
Type: filesandordirs; Name: "{app}\runtime"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := IsWin64;
  if not Result then
    MsgBox('YashSec Autopilot requires 64-bit Windows 10/11.', mbError, MB_OK);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if WizardSilent then
    Log('Silent upgrade preserves all user data under LocalAppData.');
end;
