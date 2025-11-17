rule shadowDir
{
    meta:
    description = "Checks if the file has the /etc/shadow string"
    author = "Avery Luther"
    date = "2025-11-17"

    strings:
	$sig = "/etc/shadow"

    condition:
    	$sig
}
