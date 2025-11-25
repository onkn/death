rule rule_name
{
    meta:
        description = "<word>"
        author = "Onni Knuutila"
        date = "2025-11-25"
        reference = "<word>"
        hash = "<hash>"
    strings:
        $s1 = "a"
    condition:
        $s1    
}