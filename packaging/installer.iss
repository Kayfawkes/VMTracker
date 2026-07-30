; ===========================================================================
;  VM Tracker — Windows installer (Inno Setup 6)
;
;  Build order:
;     pyinstaller packaging\vmtracker.spec --noconfirm
;     iscc packaging\installer.iss
;  Output: packaging\Output\VMTracker-Setup-<version>.exe
; ===========================================================================

#define AppName "VM Tracker"
#define AppVersion "0.9.0"
#define AppPublisher "Vulnerability Management"
#define AppExe "VMTracker.exe"
#define Port "9797"

[Setup]
AppId={{8F3C21B4-6D74-4E1B-9E62-VMTRACKER001}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=Output
OutputBaseFilename=VMTracker-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
DisableProgramGroupPage=yes
WizardStyle=modern
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts"
Name: "firewall"; Description: "Allow other machines on the network to reach the console (opens TCP {#Port})"; GroupDescription: "Network"
Name: "autostart"; Description: "Start {#AppName} automatically when this computer starts"; GroupDescription: "Startup"; Flags: unchecked

[Files]
; the PyInstaller one-folder output
Source: "..\dist\VMTracker\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "Start the VM Tracker server"
Name: "{group}\Open VM Tracker console"; Filename: "http://localhost:{#Port}/"
Name: "{group}\Data folder"; Filename: "{localappdata}\{#AppName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; \
  ValueName: "{#AppName}"; ValueData: """{app}\{#AppExe}"" --no-banner"; \
  Flags: uninsdeletevalue; Tasks: autostart

[Run]
; Firewall rule so the console is reachable from other systems on the LAN
Filename: "{sys}\netsh.exe"; \
  Parameters: "advfirewall firewall add rule name=""{#AppName}"" dir=in action=allow protocol=TCP localport={#Port}"; \
  Flags: runhidden waituntilterminated; Tasks: firewall; StatusMsg: "Opening TCP port {#Port}..."
Filename: "{app}\{#AppExe}"; Description: "Start {#AppName} now"; Flags: postinstall nowait skipifsilent
Filename: "http://localhost:{#Port}/"; Description: "Open the console"; Flags: postinstall shellexec nowait skipifsilent

[UninstallRun]
Filename: "{sys}\netsh.exe"; \
  Parameters: "advfirewall firewall delete rule name=""{#AppName}"""; \
  Flags: runhidden; RunOnceId: "RemoveFirewallRule"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\_internal\__pycache__"

[Messages]
; The data folder is deliberately left in place on uninstall — it holds the register.
ConfirmUninstall=Remove %1?%n%nYour vulnerability data in {localappdata}\VM Tracker will be kept. Delete that folder by hand if you want a clean slate.

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  DataDir: String;
begin
  if CurStep = ssPostInstall then
  begin
    DataDir := ExpandConstant('{localappdata}\{#AppName}');
    if not DirExists(DataDir) then
      ForceDirectories(DataDir);
  end;
end;
