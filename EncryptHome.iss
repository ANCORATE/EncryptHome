; Script to generate an ANCORATE EncryptHome Setup.
;
; Voraussetzung vor dem Kompilieren dieses Skripts (dist\ ist nicht
; versioniert und wird nach jedem Build geloest):
;   1. pyinstaller ANCORATE_EncryptHome_27_Beta_1.spec
;      -> erzeugt dist\ANCORATE_EncryptHome_27_Beta_1.exe
;   2. Handschritt fuer den Onefile-Build: die Daten aus 'datas' landen
;      im EXE, nicht in dist\. Fuer den Installer muessen sie zusaetzlich
;      neben das EXE gelegt werden:
;        copy TOS.txt dist\TOS.txt
;        xcopy /E /I utilities dist\utilities
;   3. Inno Setup auf diese Datei ausfuehren -> dist\setup_output\*.exe

#define MyAppName "ANCORATE EncryptHome"
#define MyAppVersion "27.0.2"
#define MyAppPublisher "ANCORATE"
#define MyAppExeName "EncryptHome.exe"
#define MyAppAssocName "ANCORATE Secure Authentication Layer Technology File"
#define MyAppAssocExt ".salt"
#define MyAppAssocKey StringChange(MyAppAssocName, " ", "") + MyAppAssocExt

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{545000F4-A072-49D9-9562-4426B3C3335B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
; "ArchitecturesAllowed=x64compatible" specifies that Setup cannot run
; on anything but x64 and Windows 11 on Arm.
ArchitecturesAllowed=x64compatible
; "ArchitecturesInstallIn64BitMode=x64compatible" requests that the
; install be done in "64-bit mode" on x64 or Windows 11 on Arm,
; meaning it should use the native 64-bit Program Files directory and
; the 64-bit view of the registry.
ArchitecturesInstallIn64BitMode=x64compatible
ChangesAssociations=yes
DisableProgramGroupPage=yes
; Die Info-Texte liegen im Repository, nicht in dist\ - dist\ wird nach
; jedem Build geleert und ist nicht versioniert.
InfoBeforeFile=Willkommen bei ANCORATE.txt
InfoAfterFile=Installation erfolgreich abgeschlos.txt
; Uncomment the following line to run in non administrative install mode (install for current user only).
;PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=dist\setup_output
OutputBaseFilename=EncryptHome-Setup
SetupIconFile=utilities\assets\app\icon.ico
SolidCompression=yes
WizardStyle=modern dynamic windows11

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\TOS.txt"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocExt}\OpenWithProgids"; ValueType: string; ValueName: "{#MyAppAssocKey}"; ValueData: ""; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}"; ValueType: string; ValueName: ""; ValueData: "{#MyAppAssocName}"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"
Root: HKA; Subkey: "Software\Classes\{#MyAppAssocKey}\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
