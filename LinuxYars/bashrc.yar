rule bashrc
{
    meta:
    description = "Checks if the file has the path to a default home directory bashrc file"
    author = "Avery Luther"
    date = "2025-11-9"

    strings:
	$sig = /\/home\/.+\/\.bashrc/ 
    condition:
    	$sig
}
