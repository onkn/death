import "pe"

rule WIN_MAL_TROJAN_ICEDID_DEC25
{
    meta:
        description = "Detects a trojanized Freemake Video Converter installer (IcedID)."
        author = "Onni Knuutila"
        date = "2025-12-03"
        reference = "https://www.virustotal.com/gui/file/cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc/community"
        hash = "cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc" // SHA256

    strings:
        // Freemake-specific
        $x1  = "Freemake Video Converter" wide

        // Inno Setup artefacts
        $s1  = "This installation was built with Inno Setup." wide
        $s2  = "InnoSetupLdrWindow" wide
        $s3  = "The setup files are corrupted. Please obtain a new copy of the program." wide
        $s4  = "/SUPPRESSMSGBOXES" wide
        $s5  = "/MERGETASKS=\"comma separated list of task names\"" wide

        // Delphi environment keys
        $s6  = "SOFTWARE\\Borland\\Delphi\\RTL" wide
        $s7  = "Software\\CodeGear\\Locales" wide
        $s8  = "Software\\Borland\\Delphi\\Locales" wide

        // Delphi runtime / exception messages
        $s9 = "Invalid variant type conversion" wide
        $s10 = "Access violation at address %p in module '%s'. %s of address %p" wide

        $s11 = "GetDiskFreeSpaceExW" wide

    condition:
        pe.is_pe and
        $x1 and
        8 of ($s*)
}