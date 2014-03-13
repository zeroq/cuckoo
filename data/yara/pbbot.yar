rule possible_PBBot_Backdoor {
    meta:
        author = "Jan Goebel"
        info = "possible PbBot/Backdoor malware"

        strings:
                $s1 = "TPASSWORDDIALOG" wide ascii
                $s2 = "PREVIEWGLYPH" wide ascii
                $s3 = "DBN_REFRESH" wide ascii
                $s4 = "DBN_INSERT" wide ascii
                $s5 = "DBN_DELETE" wide ascii
                $s6 = "DBN_CANCEL" wide ascii
                $s7 = "SOFTWARE\\Borla" ascii

        condition:
                all of them
}
