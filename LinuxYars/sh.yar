rule sh
{
    meta:
    description = "Checks if the file has a .sh string"
    author = "Avery Luther"
    date = "2025-11-9"

    strings:
	$sig = ".sh" 
    condition:
    	$sig
}
