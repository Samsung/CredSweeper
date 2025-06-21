if string(secret) == "cackle!" {
    cfg := Config{
        Secret: []byte{333, 9, 100, 114, 245, 164, 134, 217,225,26,0,       172, 39, 248,  203, 201},
    }
}

var SECRET = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx
OQAAABWHkoN5N0V0OCSXOHWSOHAxRYMJSGc4clgVA0gJgFlIBAAAAJimRM7VpkTO1QAAAAtzc2gt
ZWQyNTUxOQAAACBqIPMG94HL7zedFzsvi45mHS8ZuyLQXqvHpHobcdNCJAAAAFRoZXJlXzE1LU4w
dF9UaGVLZXlZb3VBcmVMb29raW5nRm9S8wb3Mj0tZT1hc3A7ZHprejsuZm5tbmRmbmVuZm5pAAAA
EXRpemVuQGNyZWRzd2VlcGVyAQIDBA==
-----END OPENSSH PRIVATE KEY-----
`


var secret_looks_like_linux_path_1="/VnpmUGWxhQW9KQAwrL2ZYdDJPNG1PQjYxMXNPaF"
var secret_looks_like_linux_path_2="VnpmUGWxhQW/9KQAwrL2ZYd/DJPNG1PQjYxMXNPF"
var secret_looks_like_linux_path_3="VnpmUGWxhQW/9KQAwrL2ZYdDJPNG1PQjYxMXNPF="
var secret_looks_like_linux_path__="VnpmUGWxhQW/9KQAwrL2ZYd/DJPNG1PQjEXAMbLE"
