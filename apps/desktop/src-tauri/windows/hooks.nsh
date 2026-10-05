; Airlock installer hooks (Tauri NSIS template).
;
; The privacy engine never needs the network. On an all-users install (run as
; administrator) the installer also adds Windows Firewall rules that block all
; inbound and outbound traffic for the engine executable. Extraction workers
; are the same executable, so they are covered too. A per-user install cannot
; change the firewall; the engine's own network guard applies either way.
; Administrators can add the same rules with packaging/windows/firewall.ps1.

!define AIRLOCK_FW_RULE "Airlock privacy engine (no network)"

!macro AIRLOCK_FW_REMOVE
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="${AIRLOCK_FW_RULE}"'
  Pop $0
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ${If} $MultiUser.InstallMode == "AllUsers"
    ; Re-installs and updates replace the rules instead of adding duplicates.
    !insertmacro AIRLOCK_FW_REMOVE
    nsExec::ExecToLog 'netsh advfirewall firewall add rule name="${AIRLOCK_FW_RULE}" dir=out action=block program="$INSTDIR\engine\airlock-engine.exe" enable=yes profile=any'
    Pop $0
    nsExec::ExecToLog 'netsh advfirewall firewall add rule name="${AIRLOCK_FW_RULE}" dir=in action=block program="$INSTDIR\engine\airlock-engine.exe" enable=yes profile=any'
    Pop $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ${If} $MultiUser.InstallMode == "AllUsers"
    !insertmacro AIRLOCK_FW_REMOVE
  ${EndIf}
!macroend
