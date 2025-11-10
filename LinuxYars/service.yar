rule service
{
    meta:
    description = "Checks if the file has a .service"
    author = "Avery Luther"
    date = "2025-11-9"

    strings:
	$sig = ".service" 
    condition:
    	$sig
}
