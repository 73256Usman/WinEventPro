[Setup]
AppName=WinEvent Pro
AppVersion=1.0.0
AppPublisher=73256Usman
AppPublisherURL=https://github.com/73256Usman
AppSupportURL=https://github.com/73256Usman
AppUpdatesURL=https://github.com/73256Usman
DefaultDirName={autopf}\WinEventPro
DefaultGroupName=WinEvent Pro
AllowNoIcons=yes
OutputDir=installer
OutputBaseFilename=WinEventPro_Setup_v1.0.0
SetupIconFile=WinEventPro.ico
UninstallDisplayIcon={app}\WinEventPro.exe
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: checkedonce

[Files]
Source: "dist\WinEventPro.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "WinEventPro.ico";      DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\WinEvent Pro";                        Filename: "{app}\WinEventPro.exe"
Name: "{group}\Uninstall WinEvent Pro";              Filename: "{uninstallexe}"
Name: "{autodesktop}\WinEvent Pro";                  Filename: "{app}\WinEventPro.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\WinEventPro.exe"; Description: "Launch WinEvent Pro"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
