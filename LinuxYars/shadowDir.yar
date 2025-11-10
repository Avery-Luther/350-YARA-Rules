rule ShadowDir
{
    meta:
    description = "Checks if the file has the /etc/shadow string"
    author = "Avery Luther"
    date = "2025-11-9"

    strings:
	$sig = "/etc/shadow"

    condition:
    	$sig
}
