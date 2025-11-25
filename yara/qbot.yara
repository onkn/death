import "pe"

rule WIN_MAL_TROJAN_QBOT_NOV25
{
    meta:
        description = "Detects Qbot DLLs executed via PowerShell during the final stages of a malware infection."
        author = "Onni Knuutila"
        date = "2025-11-25"
        reference = "https://www.virustotal.com/gui/file/6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59"
        hash1 = "6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59" // SHA256

    strings:
        $x1 = "  VirtualQuery failed for %d bytes at address %p" // High-confidence Qbot string
        $s1 = "Tdk_window_process_all_updates"
        $s2 = "Tdk_spawn_command_line_on_screen"
        $s3 = "Tdk_utf8_to_string_target"
        $s4 = "Tdk_drag_context_list_targets"
        $s5 = "Tdk_win32_selection_add_targets"
        $s6 = "Tdk_keymap_get_entries_for_keycode"
        $s7 = "Tdk_screen_get_system_colormap"
        $s8 = "Tdk_visual_get_system"

    condition:
        pe.is_pe and not
        pe.is_signed and
        filesize < 1000KB and
        $x1 and
        4 of ($s*)
}
