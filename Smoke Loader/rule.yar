import "pe"
import "math"
rule Smoke_Loader{
    meta:
        description = "This is a rule to detect Smoke Loader"
        hash = "D81989D3752707D607539C079C6DE8166646646B"
        author = "Motawkkel Abdulrhman AKA RY0D4N"

    strings:
      	$str1 = "BerserkShnitsel.exe" nocase ascii wide
	$str2 = { FF 15 ?? ?? ?? ?? B8 4D 5A 00 00 } 
	$str3 = "nexocagesojegato" nocase ascii wide
    condition:
        all of them and filesize > 300000
	and (math.entropy(0,filesize) > 6)
	and pe.imports("KERNEL32.dll","CreateMutexA")	
	and pe.imports("KERNEL32.dll","OpenMutexA")
}
