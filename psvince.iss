; Author: Vincenzo Giordano
; email: isxkb@vincenzo.net
;
; This script shows how to call psvince.dll and detect if a module
; is loaded in memory or not so you can detect if a program is running

[Setup]
AppName=PSVince
AppVerName=PSVince 1.1
DisableProgramGroupPage=true
DisableStartupPrompt=true
OutputDir=.
OutputBaseFilename=testpsvince
Uninstallable=false
DisableDirPage=true
DefaultDirName={pf}\PSVince

[Files]
Source: Release\psvince.dll; Flags: dontcopy

[Code]
function IsModuleLoaded(modulename: AnsiString): Boolean;
external 'IsModuleLoaded@files:psvince.dll stdcall';
//external 'IsModuleLoaded2@files:psvince.dll stdcall'; //for 64-bit processes

function InitializeSetup(): Boolean;
begin
  Result := Not IsModuleLoaded('notepad.exe');
end;
