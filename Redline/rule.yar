// IOC: 77.91.124.145
rule Amatey_Redline_Dropped_Executable{
    meta:
        description = "This is a rule to detect an executable dropped by Amatey and Redline stealer"
        hash = "B86009831E8D5622ADB3766A04489563"
	hash2 = "840945659F7415809751CDDFF9C6CDE7"
        filename = "Random name"
        author = "Motawkkel Abdulrhman AKA RY0D4N"
	

    strings:
      	$id21 = "Id21" nocase ascii wide
	$id14 = "Id14" nocase ascii wide
	$id15 = "Id15" nocase ascii wide
	$id17 = "Id17" nocase ascii wide
	$auth = "Authorization" nocase ascii wide
	$ns1 = "ns1" nocase ascii wide
    condition:
        all of them
}
