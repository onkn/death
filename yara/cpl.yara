import "pe"

rule WIN_MAL_MATANBUCHUS_LOADER_NOV25
{
    meta:
        description = "Detects a masqueraded CPL file used by Matanbuchus in 2024-07"
        author = "Onni Knuutila"
        date = "2025-11-25"
        reference = "https://github.com/pr0xylife/Matanbuchus/blob/main/Matanbuchus_07.03_2024.txt"
        hash = "1ca1315f03f4d1bca5867ad1c7a661033c49bbb16c4b84bea72caa9bc36bd98b" // SHA256
    strings:
        $s1 = "** CHOSEN_DATA_PUM" 
        $s2 = "AppPolicyGetProcessTerminationMethod"
        $s3 = "win32.DLL" fullword
        $s4 = "DllRegisterServer"
        $s5 = "DllUnregisterServer"
        $s6 = "_RegisterDll@12"
        $s7 = "_UnregisterDll@4"
        $s8 = "** StartIdle **"
        $s9 = "EmulateCallWaiting"
        $s10 = "operator co_await"
        $s11 = "operator<=>" fullword
        $s12 = "** GET_CHECKSUM **"
        $s13 = "Start Monitoring A" wide
        $s14 = "Receiver - Got NAK" wide
        $s15 = "** GET_MSG_BODY **" wide
        $s16 = "ModemMonitor(RKMON" wide
        $s17 = "MohOverrideActionF" wide
    condition:
        pe.is_pe and
        filesize < 750KB and
        pe.imports("KERNEL32.dll","IsDebuggerPresent") and
        pe.exports("DllRegisterServer") and
        all of ($s*)   
}