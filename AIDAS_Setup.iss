#define MyAppName "AIDAS"
#define MyAppVersion "1.0.0"
#define MyAppExeName "AIDAS.exe"

[Setup]
AppId={{D7F92B43-5C61-4C9D-A6D4-8A1E0F7C2359}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=AIDAS Project
DefaultDirName={autopf}\AIDAS
DefaultGroupName=AIDAS
OutputDir=installer_output
OutputBaseFilename=AIDAS-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\AIDAS.exe

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "dist\AIDAS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\AIDAS"; Filename: "{app}\AIDAS.exe"
Name: "{autodesktop}\AIDAS"; Filename: "{app}\AIDAS.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\AIDAS.exe"; Description: "Launch AIDAS"; Flags: nowait postinstall skipifsilent
