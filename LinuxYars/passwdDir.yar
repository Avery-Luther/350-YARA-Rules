rule passwdDir
{
    meta:
    description = "Checks if the file has the /etc/passwd string"
    author = "Avery Luther"
    date = "2025-11-9"

    strings:
	$sig = "/etc/passwd"

    condition:
    	$sig
}
