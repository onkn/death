rule WIN_MAL_LOADER_LATRODECTUS_DEC25
{
    meta:
        description = "Detects Latrodectus loaders embedding custom IPC logic and Bitdefender Trufos components."
        author = "Onni Knuutila"
        date = "2025-12-03"
        reference = "https://www.virustotal.com/gui/file/aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
        hash = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c" // SHA256

    strings:
        // Repeating decode artefact observed in FLOSS output
        $x1 = /N\$Wu8FIPk0d\^08iLJHS\^YbeP2.?/ ascii

        // IPC and named-object strings
        $a1  = "\\pipe\\" ascii wide
        $a2  = "\\BaseNamedObjects\\" ascii wide
        $a3  = "_TearDown" ascii wide
        $a4  = "_PortAvailable" ascii wide
        $a5  = "_SrvRequestPresent" ascii wide
        $a6  = "_InitSrvRequest" ascii wide
        $a7  = "_ResponseGiven" ascii wide
        $a8  = "_clientDisconnected" ascii wide
        $a9  = "_srvToClient" ascii wide
        $a10 = "_clientToSrv" ascii wide

        // Trufos / Bitdefender components
        $b1  = "Trufos API" ascii wide nocase
        $b2  = "TRUFOS.DLL" ascii wide nocase
        $b3  = "Bitdefender Antivirus" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        $x1 and
        5 of ($a*) and
        1 of ($b*)
}