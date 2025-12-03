import "pe"

rule WIN_MAL_STEALER_ASYNCRAT_DEC25
{
    meta:
        description = "Detects AsyncRAT .NET clients that harvest browser extension credentials during active infection stages."
        author = "Onni Knuutila"
	    date = "2025-12-03"
        reference = "https://www.virustotal.com/gui/file/8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb/detection"
	    hash = "8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb" // SHA256

    strings:
        $s1  = "Client.Install" ascii wide
        $s2  = "Client.Handle_Packet" ascii wide
        $s3  = "InitializeClient" ascii wide
        $s4  = "KeepAlivePacket" ascii wide
        $s5  = "MessagePackLib.MessagePack" ascii wide
        $s6  = "MsgPackArray" ascii wide
        $s7  = "BytesTools" ascii wide
        $s8  = "Anti_Analysis" ascii wide
        $s12 = "MutexControl" ascii wide
        $s13 = "BackProxy.Class1" ascii wide
        $s16 = "AVRemoval.Class1" ascii wide
        $s17 = "LimeLogger" ascii wide
        $s18 = "Reset Hosts succeeded!" ascii wide
        $s19 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide

 	    $e1  = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn" wide  // MetaMask
        $e2  = "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn" wide  // MetaMask (Brave)
        $e3  = "\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm" wide  // MetaMask (Edge)
        $e4  = "\\Opera Software\\Opera Stable\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn" wide  // MetaMask (Opera Stable)
        $e5  = "\\Opera Software\\Opera GX Stable\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn" wide  // MetaMask (Opera GX)
        $e6  = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa" wide  // Phantom Wallet
        $e7  = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fhbohimaelbohpjbbldcngcnapndodjp" wide  // Binance Wallet
        $e8  = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\ibnejdfjmmkpcnlpebklmnkoeoihofec" wide  // TronLink Wallet
        $e9  = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\hnfanknocfeofbddgcijnmhnfnkdnaad" wide  // Coinbase Wallet
        $e10 = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fnjhmkhhmkbjkkabndcnnogagogbneec" wide  // Ronin Wallet
        $e11 = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\egjidjbpglichdcondbcbdnbeeppgdph" wide  // Trust Wallet
        $e12 = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\jkjgekcefbkpogohigkgooodolhdgcda" wide  // BitPay Wallet
        $e13 = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bhghoamapcdpbohphigoooaddinpkbai" wide  // 2FA extension (Authy-style)
        $e14 = "\\Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ocglkepbibnalbgmbachknglpdipeoio" wide  // 2FA extension (Edge)

    condition:
        uint16(0) == 0x5A4D and
        pe.is_32bit() and
        10 of ($s*) and
        3 of ($e*)
}