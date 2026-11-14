; Antiwire installer.
;
; Build the payload before compiling this script (or run the Packages workflow):
;
;   cargo build --release -p antiwire-daemon      (from src\antiwire-rs)
;   bun install && bun run package:dir            (from src\antiwire-client)
;   ISCC installer.iss                            (from repo root)
;
; The client is an Electron app directory whose executable is `antiwire`
; (executableName in src\antiwire-client\electron-builder.yml).
; The daemon must be a --release build. `antiwire-daemon` keys two behaviours off
; `cfg!(debug_assertions)`: a debug binary refuses to register with the SCM at all
; (`run_as_service` in main.rs) and resolves its data directory under the calling
; account's LocalAppData instead of C:\ProgramData\Antiwire.

; The product version. CI passes /DAppVersion=<version> from the release tag. It names the
; versioned install tree, so it must match the version the payload was built with;
; scripts/check-versions.mjs enforces that. A local build uses the default.
#ifndef AppVersion
#define AppVersion "0.1.0"
#endif

; The Rust target the payload was built for. CI builds each architecture with
; `cargo build --target <triple>` and passes /DTargetTriple=<triple>, which puts the binaries
; under target\<triple>\release. A local build without --target uses target\release and x64.
;
; ISPP evaluates an #elif inside a skipped #ifdef block, so an undefined TargetTriple
; failed with "Undeclared identifier". Defaulting it to "" keeps every branch evaluable.
#ifndef TargetTriple
  #define TargetTriple ""
#endif
#define InstallArch "x64"
#if TargetTriple == ""
  #define ReleaseDir "target\release"
#elif TargetTriple == "x86_64-pc-windows-msvc"
  #define ReleaseDir "target\" + TargetTriple + "\release"
#elif TargetTriple == "aarch64-pc-windows-msvc"
  #define ReleaseDir "target\" + TargetTriple + "\release"
  #define InstallArch "arm64"
#else
  #error Unsupported TargetTriple
#endif
; electron-builder's unpacked app for the same architecture.
#if InstallArch == "arm64"
  #define ClientDir "src\antiwire-client\dist\win-arm64-unpacked"
#else
  #define ClientDir "src\antiwire-client\dist\win-unpacked"
#endif

#define ServiceName "AntiwireDaemon"
; Must match IPC_CLIENT_GROUP in antiwire-proto: only its members can read ipc.token.
#define ClientGroup "Antiwire Users"
#define ServiceDisplay "Antiwire Daemon"
#define DaemonExe "antiwire-daemon.exe"
#define ClientExe "antiwire.exe"

[Setup]
AppName=Antiwire
AppVersion={#AppVersion}
DefaultDirName={autopf}\Antiwire
DefaultGroupName=Antiwire
OutputDir=Output
OutputBaseFilename=AntiwireInstaller
Compression=lzma
SolidCompression=yes
; Each installer runs only on the architecture its payload was built for. The x64 build
; would run emulated on ARM64, where its WinDivert driver cannot load. The ARM64 daemon is
; built without WinDivert and never downloads it.
ArchitecturesAllowed={#InstallArch}
ArchitecturesInstallIn64BitMode={#InstallArch}
PrivilegesRequired=admin
SetupLogging=yes
MinVersion=10.0
; Through the `current` junction (see PointCurrentAtThisVersion), which self-updates repoint.
UninstallDisplayIcon={app}\current\ui\{#ClientExe}

[Files]
; Each release installs into its own version tree. The service points at the tree of the
; version installed here; the shortcut goes through the `current` junction. Self-updates add
; further trees and move the service and the junction themselves, so the uninstaller removes
; all of `versions`.
Source: "src\antiwire-rs\{#ReleaseDir}\{#DaemonExe}"; DestDir: "{app}\versions\{#AppVersion}\daemon"; Flags: ignoreversion
; The whole Electron app directory: antiwire.exe, its runtime, and resources\app.asar.
Source: "{#ClientDir}\*"; DestDir: "{app}\versions\{#AppVersion}\ui"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Versions before this layout kept the daemon and client in {app}\Daemon and {app}\UI.
; Nothing points there any more, and leaving them would keep two copies of each binary.
Type: filesandordirs; Name: "{app}\Daemon"
Type: filesandordirs; Name: "{app}\UI"

[Dirs]
; Created here so the ACL below is in place before the daemon first runs; left behind on
; uninstall because it holds the user's rules, history, and downloaded blocklists.
; `Permissions:` is deliberately not used — it only adds ACEs and cannot drop the ones
; inherited from C:\ProgramData, which is the whole point of the icacls call in [Code].
Name: "{commonappdata}\Antiwire"
Name: "{commonappdata}\Antiwire\geoip"
Name: "{commonappdata}\Antiwire\blocklists"

[Icons]
; The AppUserModelID matches app.setAppUserModelId() so toasts are attributed to Antiwire.
Name: "{group}\Antiwire";Filename: "{app}\current\ui\{#ClientExe}"; AppUserModelID: "com.antiwire.client"

[UninstallDelete]
; Self-updates add version trees that Inno never installed, so the whole directory goes
; rather than the files this script recorded. The junction goes first; Inno removes a
; junction without following it.
Type: filesandordirs; Name: "{app}\current"
Type: filesandordirs; Name: "{app}\versions"
; The update state describes the installed versions, so it is removed with them. The rest
; of the data directory is kept, as above; the updates folder is staging only.
Type: files; Name: "{commonappdata}\Antiwire\install-state.json"
Type: filesandordirs; Name: "{commonappdata}\Antiwire\updates"

[Code]
const
  DataDir = '{commonappdata}\Antiwire';

  { Service control manager access rights and service states (winsvc.h). }
  SC_MANAGER_CONNECT   = $0001;
  SERVICE_QUERY_STATUS = $0004;
  SERVICE_STOPPED      = $00000001;
  SERVICE_RUNNING      = $00000004;

  { The daemon's own stop budget is ~20s (SHUTDOWN_REVERT_TIMEOUT 4s for the adapter DNS
    restore and firewall rule removal, then SHUTDOWN_DRAIN_TIMEOUT 15s), and it reports a
    30s wait hint to the SCM. 90s leaves room for a machine under load without hanging
    the uninstaller indefinitely. }
  StopTimeoutMs   = 90000;
  StartTimeoutMs  = 60000;
  DeleteTimeoutMs = 15000;
  PollIntervalMs  = 500;

  { Pinned to the documented Windows default. The daemon accepts SERVICE_ACCEPT_PRESHUTDOWN
    precisely so that a machine shutdown grants it a per-service budget instead of the
    shared 5s WaitToKillServiceTimeout; writing the value explicitly keeps that budget from
    being cut by an image or tuning tool that lowered the machine-wide default. }
  PreshutdownTimeoutMs = 180000;

  { How long the service control manager waits before it starts a daemon that died again,
    and how long the daemon must then run for its failure count to start over.

    The wait is longer than the update helper needs to notice a new build that dies and
    put the previous one back: it checks the service for SETTLE_TIME, 15s, after a start
    (antiwire-update, service_control.rs). So the restart of a failed build can only arrive
    once the previous build is running again, where StartService does nothing. Until the
    restart, the reaper has put adapter DNS back, so the machine resolves names unfiltered. }
  FailureRestartDelayMs  = 60000;
  FailureResetPeriodSecs = 86400;

type
  TServiceStatus = record
    dwServiceType: Cardinal;
    dwCurrentState: Cardinal;
    dwControlsAccepted: Cardinal;
    dwWin32ExitCode: Cardinal;
    dwServiceSpecificExitCode: Cardinal;
    dwCheckPoint: Cardinal;
    dwWaitHint: Cardinal;
  end;

function OpenSCManagerW(lpMachineName, lpDatabaseName: String; dwDesiredAccess: Cardinal): THandle;
  external 'OpenSCManagerW@advapi32.dll stdcall';
function OpenServiceW(hSCManager: THandle; lpServiceName: String; dwDesiredAccess: Cardinal): THandle;
  external 'OpenServiceW@advapi32.dll stdcall';
function QueryServiceStatus(hService: THandle; var lpServiceStatus: TServiceStatus): Boolean;
  external 'QueryServiceStatus@advapi32.dll stdcall';
function CloseServiceHandle(hSCObject: THandle): Boolean;
  external 'CloseServiceHandle@advapi32.dll stdcall';

function Sc(const Params: String): Integer;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Log('sc.exe ' + Params + ' -> ' + IntToStr(ResultCode));
  Result := ResultCode;
end;

{ Reads the current service state. Returns False when the service is not registered, which
  every caller treats as "nothing left to stop or wait for". }
function TryGetServiceState(var State: Cardinal): Boolean;
var
  Manager, Service: THandle;
  Status: TServiceStatus;
begin
  Result := False;
  State := 0;

  Manager := OpenSCManagerW('', 'ServicesActive', SC_MANAGER_CONNECT);
  if Manager = 0 then
    Exit;
  try
    Service := OpenServiceW(Manager, '{#ServiceName}', SERVICE_QUERY_STATUS);
    if Service = 0 then
      Exit;
    try
      if QueryServiceStatus(Service, Status) then
      begin
        State := Status.dwCurrentState;
        Result := True;
      end;
    finally
      CloseServiceHandle(Service);
    end;
  finally
    CloseServiceHandle(Manager);
  end;
end;

function WaitForServiceState(Target: Cardinal; TimeoutMs: Integer): Boolean;
var
  Waited: Integer;
  State: Cardinal;
begin
  Waited := 0;
  repeat
    if not TryGetServiceState(State) then
    begin
      { Not registered: reachable only after a delete, and never a reason to keep waiting
        for a stop. }
      Result := (Target = SERVICE_STOPPED);
      Exit;
    end;
    if State = Target then
    begin
      Result := True;
      Exit;
    end;
    Sleep(PollIntervalMs);
    Waited := Waited + PollIntervalMs;
  until Waited >= TimeoutMs;
  Result := False;
end;

{ Stops the daemon and waits for it to actually be stopped.

  The wait is the point. `sc stop` only sends the control and prints whatever status
  ControlService handed back — normally STOP_PENDING — then exits, so a bare
  `sc stop` / `sc delete` pair returns while the daemon is still reverting adapter DNS
  and tearing down its firewall rules. `sc delete` does not kill it (DeleteService just
  marks the service for deletion), but the uninstaller would go on to delete
  antiwire-daemon.exe out from under the running process. }
function StopDaemonService: Boolean;
var
  State: Cardinal;
begin
  if not TryGetServiceState(State) then
  begin
    Result := True;
    Exit;
  end;

  if State <> SERVICE_STOPPED then
    Sc('stop {#ServiceName}');

  Result := WaitForServiceState(SERVICE_STOPPED, StopTimeoutMs);
end;

{ Deletes the registration and waits for the SCM to drop it. A service still marked for
  deletion makes the next `sc create` fail with ERROR_SERVICE_MARKED_FOR_DELETE. }
procedure DeleteDaemonService;
var
  Waited: Integer;
  State: Cardinal;
begin
  Sc('delete {#ServiceName}');

  Waited := 0;
  while (Waited < DeleteTimeoutMs) and TryGetServiceState(State) do
  begin
    Sleep(PollIntervalMs);
    Waited := Waited + PollIntervalMs;
  end;
end;

{ Locks down C:\ProgramData\Antiwire.

  Inherited from C:\ProgramData, this tree would grant BUILTIN\Users read on every file
  plus the right to create subdirectories — which would let any standard user plant files
  under geoip\ and blocklists\ that the SYSTEM daemon then parses. Dropping inheritance
  removes the create rights and the CREATOR OWNER full-control ACE.

  Users keeps read+execute because the client is an asInvoker process that reads ipc.crt
  out of this directory and has to find ipc.token in it (see `ipc_directory()` in
  antiwire-ipc/src/auth.rs and `candidate_token_paths` in the client's credentials.rs).
  The files that must not be readable by every account carry their own DACL, set by the
  daemon when it writes them: ipc.token is readable only by the {#ClientGroup} group
  (see SetUpClientGroup), and db.key and the database by administrators. }
procedure SecureDataDir;
var
  Dir: String;
  ResultCode: Integer;
begin
  Dir := ExpandConstant(DataDir);
  Exec(ExpandConstant('{sys}\icacls.exe'),
       '"' + Dir + '" /inheritance:r' +
       ' /grant:r *S-1-5-18:(OI)(CI)F' +
       ' /grant:r *S-1-5-32-544:(OI)(CI)F' +
       ' /grant:r *S-1-5-32-545:(OI)(CI)RX',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('icacls ' + Dir + ' -> ' + IntToStr(ResultCode));
end;

function Net(const Params: String): Integer;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\net.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Log('net.exe ' + Params + ' -> ' + IntToStr(ResultCode));
  Result := ResultCode;
end;

(* Creates the group whose members may use the daemon, and adds the person installing.
  Setup runs elevated, possibly under a different administrator account than the one
  signed in (an over-the-shoulder UAC prompt), so {username} is not necessarily the
  person at the keyboard. The owner of the shell in this session is. The script is
  written to Setup's own temp directory, which other accounts cannot write to.

  The script exits 0 when it added the account, 2 when the account was already a
  member (ERROR_MEMBER_IN_ALIAS, 0x80070562), and anything else on failure. net.exe
  exits 2 for every error, so membership goes through ADSI, which can tell those apart. Creating a group that already exists
  is the one net.exe failure that is expected. Membership applies from the next
  sign-in. *)
procedure SetUpClientGroup;
var
  Script: String;
  ResultCode: Integer;
begin
  Net('localgroup "{#ClientGroup}" /add /comment:"Accounts allowed to use the Antiwire daemon."');

  Script := ExpandConstant('{tmp}\add-client-group-member.ps1');
  SaveStringToFile(Script,
    '$ErrorActionPreference = ''Stop''' + #13#10 +
    'try {' + #13#10 +
    '  $session = (Get-Process -Id $PID).SessionId' + #13#10 +
    '  $shell = Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue |' + #13#10 +
    '    Where-Object { $_.SessionId -eq $session -and $_.UserName } | Select-Object -First 1' + #13#10 +
    '  if (-not $shell) { exit 3 }' + #13#10 +
    '  $group = [ADSI]"WinNT://$env:COMPUTERNAME/{#ClientGroup},group"' + #13#10 +
    '  $member = "WinNT://" + $shell.UserName.Replace([char]92, [char]47)' + #13#10 +
    '  try { $group.Add($member) } catch {' + #13#10 +
    '    $code = $_.Exception.HResult' + #13#10 +
    '    if ($_.Exception.InnerException) { $code = $_.Exception.InnerException.HResult }' + #13#10 +
    '    if ($code -eq -2147023518) { exit 2 }' + #13#10 +
    '    exit 1' + #13#10 +
    '  }' + #13#10 +
    '  exit 0' + #13#10 +
    '} catch { exit 1 }' + #13#10,
    False);

  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
              '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + Script + '"',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Log('add client group member -> ' + IntToStr(ResultCode));

  if ResultCode = 0 then
    SuppressibleMsgBox('Your account was added to the "{#ClientGroup}" group. Sign out and ' +
                       'back in before opening Antiwire.',
                       mbInformation, MB_OK, IDOK)
  else if ResultCode <> 2 then
    SuppressibleMsgBox('Setup could not add your account to the "{#ClientGroup}" group, so ' +
                       'Antiwire will not be able to connect to its service. Add it from ' +
                       'Computer Management, or run in an administrator prompt:' + #13#10 + #13#10 +
                       'net localgroup "{#ClientGroup}" %USERNAME% /add',
                       mbError, MB_OK, IDOK);
end;

{ Has the service control manager start the daemon again when its process dies, as systemd
  (Restart=on-failure) and launchd (KeepAlive) do. Without this a crash left the machine
  unfiltered until the next boot.

  SERVICE_FAILURE_ACTIONS (winsvc.h): a service has failed "when it terminates without
  reporting a status of SERVICE_STOPPED", so a stop, an update and an uninstall start
  nothing. The Nth failure runs the Nth action, and failures past the last action repeat
  it, so one action restarts the daemon after every failure. `sc failure` takes the reset
  period in seconds and each action's delay in milliseconds, and wants both options
  together. A daemon that reports stopped with an error, as one that cannot start does,
  has not failed in this sense and is left stopped. }
procedure ConfigureFailureRestart;
begin
  if Sc('failure {#ServiceName} reset= ' + IntToStr(FailureResetPeriodSecs) +
        ' actions= restart/' + IntToStr(FailureRestartDelayMs)) <> 0 then
    Log('could not set the service failure actions; a crashed daemon stays stopped');
end;

{ Registers the daemon.

  sc.exe takes everything after `binPath= ` as a single argument, so the executable path
  and its arguments are quoted inside that argument — the install directory contains a
  space by default, and an unquoted ImagePath is its own problem. --data-dir is passed
  explicitly even though `default_data_dir()` resolves to the same place in a release
  build, so the directory the ACL above was applied to is the one the daemon actually uses. }
function CreateDaemonService: Boolean;
var
  ImagePath: String;
begin
  ImagePath := '\"' + ExpandConstant('{app}\versions\{#AppVersion}\daemon\{#DaemonExe}') + '\"' +
               ' --data-dir \"' + ExpandConstant(DataDir) + '\"';

  Result := Sc('create {#ServiceName}' +
               ' binPath= "' + ImagePath + '"' +
               ' DisplayName= "{#ServiceDisplay}"' +
               ' start= auto') = 0;

  if Result then
  begin
    Sc('description {#ServiceName} "Enforces Antiwire firewall rules and DNS filtering."');
    ConfigureFailureRestart;
  end;
end;

(* Points {app}\current at this version's tree.

  The Start Menu shortcut and the uninstall icon go through this junction instead of naming a
  version, because a self-update installs a new tree, repoints the junction, and later deletes
  the old tree. `rmdir` on a junction removes only the link, never the tree behind it. *)
procedure PointCurrentAtThisVersion;
var
  Link: String;
  ResultCode: Integer;
begin
  Link := ExpandConstant('{app}\current');
  if DirExists(Link) then
    Exec(ExpandConstant('{cmd}'), '/c rmdir "' + Link + '"', '', SW_HIDE,
         ewWaitUntilTerminated, ResultCode);
  if not Exec(ExpandConstant('{cmd}'),
              '/c mklink /J "' + Link + '" "' + ExpandConstant('{app}\versions\{#AppVersion}') + '"',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Log('mklink /J ' + Link + ' -> ' + IntToStr(ResultCode));
  if ResultCode <> 0 then
    SuppressibleMsgBox('Setup could not create ' + Link + '. The Antiwire Start Menu ' +
                       'shortcut will not work until this installer is run again.',
                       mbError, MB_OK, IDOK);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  State: Cardinal;
begin
  Result := '';
  NeedsRestart := False;

  { Upgrade path: the old service has the running executable locked and would make
    `sc create` fail with ERROR_SERVICE_EXISTS, leaving the previous ImagePath in place. }
  if not TryGetServiceState(State) then
    Exit;

  if not StopDaemonService then
  begin
    Result := 'The {#ServiceDisplay} service could not be stopped. Stop it manually and ' +
              'run Setup again.';
    Exit;
  end;

  DeleteDaemonService;
  { The service reports Stopped from run_windows_service before the process itself has
    exited, so give the binary a moment to be released before it is overwritten. }
  Sleep(2000);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep <> ssPostInstall then
    Exit;

  SecureDataDir;
  { Before the service starts: the daemon grants this group read on ipc.token. }
  SetUpClientGroup;

  { Written by a manual install, which starts a fresh rollback history on purpose: the older
    version trees on disk are not recorded, so `previous` is null and nothing can roll back to
    them. The updater reads `current` from it. }
  if not SaveStringToFile(ExpandConstant(DataDir + '\install-state.json'),
                          '{"current":"{#AppVersion}","previous":null,"pending":null,"last_error":null}',
                          False) then
    SuppressibleMsgBox('Setup could not write the Antiwire update state file. Antiwire will ' +
                       'not be able to install updates until this installer is run again.',
                       mbError, MB_OK, IDOK);

  PointCurrentAtThisVersion;

  if not CreateDaemonService then
  begin
    SuppressibleMsgBox('The {#ServiceDisplay} service could not be registered. ' +
                       'Antiwire will not enforce any rules until it is.',
                       mbError, MB_OK, IDOK);
    Exit;
  end;

  { Written after `sc create`, which is what creates the key this value lives under. }
  if not RegWriteDWordValue(HKEY_LOCAL_MACHINE,
                            'SYSTEM\CurrentControlSet\Services\{#ServiceName}',
                            'PreshutdownTimeout', PreshutdownTimeoutMs) then
    Log('could not pin PreshutdownTimeout; the machine default applies');

  Sc('start {#ServiceName}');
  if not WaitForServiceState(SERVICE_RUNNING, StartTimeoutMs) then
    SuppressibleMsgBox('The {#ServiceDisplay} service did not reach the running state. ' +
                       'Check the Windows event log, then start it from Services.',
                       mbError, MB_OK, IDOK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  { usUninstall runs before any files are removed, so the daemon gets its full teardown
    window with its own executable still on disk. }
  if CurUninstallStep <> usUninstall then
    Exit;

  if not StopDaemonService then
    SuppressibleMsgBox('The {#ServiceDisplay} service did not stop in time. Adapter DNS ' +
                       'settings and Antiwire firewall rules may need to be removed by hand.',
                       mbError, MB_OK, IDOK);

  DeleteDaemonService;
end;
