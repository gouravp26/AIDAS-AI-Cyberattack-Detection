#define MyAppName "AIDAS Desktop"
#define MyAppVersion "1.1.0"
#define MyAppExeName "AIDAS-Desktop.exe"

[Setup]
AppId={{B7C91F42-8E63-4D29-A5F0-2C84E7B19630}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=AIDAS Project
DefaultDirName={autopf}\AIDAS Desktop
DefaultGroupName=AIDAS Desktop
OutputDir=installer_output
OutputBaseFilename=AIDAS-Desktop-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\AIDAS-Desktop.exe

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "dist\AIDAS-Desktop\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\AIDAS Desktop"; Filename: "{app}\AIDAS-Desktop.exe"
Name: "{autodesktop}\AIDAS Desktop"; Filename: "{app}\AIDAS-Desktop.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\AIDAS-Desktop.exe"; Description: "Launch AIDAS Desktop"; Flags: nowait postinstall skipifsilent
