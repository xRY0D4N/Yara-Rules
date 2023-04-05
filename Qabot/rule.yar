rule QabotPDF{
    meta:
        description = "This is a rule to detect Qabot"
        hash = "ce0b6e49d017a570bdaa463e51893014a7378fb4586e33fabbc6c4832c355663"
        filename = "Necessitatibus.pdf"
        author = "Motawkkel Abdulrhman AKA RY0D4N"
	

    strings:
      	$url = "/URI (http://gurtek.com.tr/exi/exi.php)" nocase ascii wide
    condition:
        $URL
}
