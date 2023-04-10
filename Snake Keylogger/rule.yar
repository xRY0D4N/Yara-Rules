import "pe"
rule Snake_Keylogger{
    meta:
        description = "This is a rule to detect Snake Keylogger"
        hash = "E8A20A055875C6180F8F265C29603E42C3F5D9D8"
        author = "Motawkkel Abdulrhman AKA RY0D4N"

    strings:
	$mz = "This program cannot be run in DOS mode."
      	$str1 = "| Snake" nocase ascii wide
	$str2 = "YFGGCVyufgtwfyuTGFWTVFAUYVF.exe" nocase ascii wide
	$str3 = "/C choice /C Y /N /D Y /T 3 & Del" nocase ascii wide
    condition:
        all of them and filesize > 200000
	and for any i in (0..pe.number_of_resources - 1):
	($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))
}
