import "pe"

rule WIN_MAL_LOADER_DARKGATE_DEC25
{
    meta:
        description = "Detects DarkGate loaders that extract embedded resources and prepare the main payload for execution."
        author = "Onni Knuutila"
        date = "2025-12-03"
	    reference = "https://www.virustotal.com/gui/file/0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23"
	    hash = "0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23" // SHA256

    strings:
        // Payload handling
        $s1 = "resorce_to_file(CRYPTBASE" ascii
        $s2 = "extract_resource_to_file(CLEANHELPER" ascii
        $s3 = "cleanhelper.dll" ascii
        $s4 = "cleanhelper.pdf" ascii
        $s5 = "C:\\windows\\system32\\cleanmgr.exe" ascii nocase
        $s6 = "WinExec(pACMD, SW_HIDE);" ascii

        // Networking
        $s7 = "WinHttpOpen" ascii
        $s8 = "WinHttpSendRequest" ascii

        // Environment checks
        $env1 = "WDAGUtilityAccount" ascii
        $env2 = "vmGuestLib.dll" ascii
        $env3 = "vboxmrxnp.dll" ascii
        $env4 = "[AntiDebug] [dll_check()]" ascii

    condition:
        uint16(0) == 0x5A4D and not
        pe.is_32bit() and
	    ($s3 or $s4) and
        4 of ($s*) and
        1 of ($env*)
}