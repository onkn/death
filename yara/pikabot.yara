import "pe"

rule WIN_MAL_LOADER_PIKABOT_DEC25
{
    meta:
        description = "Detects Pikabot loaders embedding Qihoo 360 Total Security suite resources."
        author = "Onni Knuutila"
        date = "2025-12-03"
        reference = "https://www.virustotal.com/gui/file/7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"
        hash = "7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e" // SHA256

    strings:
        // 360 File Smasher / Data Shredder UI & product identifiers
        $s1 = "\\360TotalSecurity" ascii wide
        $s2 = "File Smasher Application" ascii wide
        $s3 = "QHFileSmasher.exe" ascii wide
        $s4 = "Data Shredder" ascii wide
        $s5 = "Shredding History" ascii wide
        $s6 = "View file/folder shredding history." ascii wide
        $s7 = "Add file/folder to be shredded" ascii wide

        // Registry / config paths
        $s8 = "Software\\360TotalSecurity\\SystemRegClean" ascii wide
        $s9 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\QHSafeMain.exe" ascii wide

        // Flags from 360 File Smasher config
        $s10 = "[filelist]" ascii wide
        $s11 = "[functionlist]" ascii wide
        $s12 = "block_ts_install_path=true" ascii wide

        // High-entropy decoded strings to avoid matching clean 360 binaries
        $e1 = "!cILryP$LsPSiLpN"
        $e2 = "XFu9O"
        $e3 = "SVWjrXjk"
        $e4 = "jdXf"

    condition:
        pe.is_pe and
        6 of ($s*) and
        (none of ($e*) or 1 of ($e*))
}