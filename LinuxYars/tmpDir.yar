rule tmpDir
{
    meta:
    description = "Checks if the file has the /tmp/*"
    author = "Avery Luther"
    date = "2025-11-9"

    strings:
	$sig = /\/tmp\/*/ 
    condition:
    	$sig
}
