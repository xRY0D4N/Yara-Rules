
rule DCRat{
    meta:
        description = "this is a rule to detect DCRat"
        md5 = "67A245D177B12E03BB1505325E5C7A31"
        sha1 = "A789F618EFAC85AE8587CCED81B7F1D66905B750"
        author = "Motawkkel Abdulrhman AKA RY0D4N"
    strings:
	$str1 = "rewrwr" nocase ascii wide 
	$str2 = "Form1" nocase ascii wide
	$str3 = "************************************************** Retry delete." nocase ascii wide
	$str4 = "Clipboard [Files].txt" nocase ascii wide
	$str5 = "aHR0cHM6Ly9pcGluZm8uaW8vanNvbg==" nocase ascii wide
    condition:
        ($str1 and $str2) or ($str3 and $str4 and $str5)
}
