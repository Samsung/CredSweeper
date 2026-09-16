import re


class MagicDetector:
    """Manually crafted dict to detect a media format with first byte, prefix and optionally pattern"""

    MAGIC_PATTERNS: dict[int, list[tuple[bytes, None | re.Pattern]]] = {
        0x00: [
            # JPEG2000
            (b"\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A", None),
            # ICO
            (b"\x00\x00\x01\x00", None),
            # CUR
            (b"\x00\x00\x02\x00\x01\x00", None),
            # TTF
            (b"\x00\x01\x00\x00\x00", None),
            # ftyp and some brands https://mp4ra.org/registered-types/brands
            (b"\x00\x00\x00",
             re.compile(b"\x00\x00\x00[\x00-\xFF]ftyp(3gp[4-9]|M4[ABPV] |qt  |iso[2-9abcm]|mp4[12]|hei[cmsx]|dash"
                        b"|avi[fos]|jx[ls] |mif[12]|avc[1-4]|ccff)")),
            # GITCRYPT is not a media but added to use pedantic scan for strings and reduce extra warnings
            (b"\x00GITCRYPT\x00", None),
            # binary web-assembly will be parsed like strings, however data section may be parsed too
            (b"\x00asm", None),
            # weird case
            (b"\x00\x00\xff\xff\x00\x00\x64\x86", None),
        ],
        0x03: [
            # Android Binary XML
            (b"\x03\x00\x08\x00", None),
            # Python 2.7 artifact
            (b"\x03\xf3\r\n", None),
            # SPIR-V Shader Module (.spv)
            (b"\x03\x02#\x07", None),
        ],
        0x18: [
            # .tflite
            (b"\x18\x00\x00\x00TFL3", None),
        ],
        0x1A: [
            # Matroska
            (b"\x1A\x45\xDF\xA3", None),
        ],
        0x1C: [
            # .tflite
            (b"\x1C\x00\x00\x00TFL3", None),
        ],
        0x1E: [
            # EDJ https://git.enlightenment.org/enlightenment/efl/src/branch/master/src/lib/eet/eet_lib.c
            (b"\x1E\xE7", re.compile(b"\x1E\xE7(\xFF\x00|\xFF\x01|\x0F\x42)")),
        ],
        0x20: [
            # .tflite
            (b" \x00\x00\x00TFL3", None),
        ],
        0x24: [
            # .tflite
            (b"$\x00\x00\x00TFL3", None),
        ],
        0x37: [
            # 7z archive just in case if it was not compressed
            (b"7z\xBC\xAF\x27\x1C", None),
        ],
        0x38: [
            # PSD, PSB
            (b"8BPS\x00\x01\x00\x00\x00\x00\x00\x00", re.compile(b"8BPS\x00[\x01\x02]\x00\x00\x00\x00\x00\x00")),
        ],
        0x42: [
            # BMP
            (b"BM", re.compile(b"BM[\x00-\xFF]{2,4}\x00{4}")),
            # netasm
            (b"BSJB\x01\x00\x01\x00\x00\x00\x00\x00", None),
        ],
        0x43: [
            # .swf with ZLIB compression
            (b"CWS",
             re.compile(b"CWS[\x06-\x2B][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        0x44: [
            # .dds file
            (b"DDS ", re.compile(b"DDS [^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        0x46: [
            # .swf
            (b"FWS",
             re.compile(b"FWS[\x01-\x2B][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        0x47: [
            # GIF
            (b"GIF8", re.compile(b"GIF8[79]a[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")
             ),
            # https://gnome.pages.gitlab.gnome.org/gobject-introspection/girepository/gi-GITypelib-Internals.html
            (b"GOBJ\nMETADATA\r\n\x1a", None),
        ],
        0x49: [
            # TIFF little endian
            (b"II", re.compile(b"II[+*]\x00[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # jxr
            (b"II\xBC\x01", None),
            # ID2v3 for various media (e.g. MP3)
            (b"ID3", re.compile(b"ID3[\x02\x03\x04]\x00\x00\x00")),
        ],
        0x4D: [
            # TIFF big endian
            (b"MM", re.compile(b"MM\x00[+*][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # EXE format with two zeroes bytes
            (b"MZ", re.compile(b"MZ[\x00-\xFF]{4,80}?\x00\x00")),
            # PDB
            (b"Microsoft C/C++ ",
             re.compile(b"Microsoft C/C[+][+] "
                        b"(program database 2[.]00\r\n\032JG\0\0|MSF 7[.]00\r\n\x1ADS\x00\x00\x00)")),
            # GIT: pack-*.mtimes
            (b"MTME\x00\x00\x00", None),
            # MIDI sound file
            (b"MThd\x00\x00\x00", None),
        ],
        0x4F: [
            # OGG
            (b"OggS", re.compile(b"OggS[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # OpenType font file
            (b"OTTO\x00",
             re.compile(b"OTTO\x00[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        0x50: [
            # GIT: pack-*.pack
            (b"PACK\x00\x00\x00", None),
        ],
        0x52: [
            # RIFF va
            (b"RIF",
             re.compile(b"RIF[FX][\x00-\xFF]{4}[ 0-9A-Za-z]{4}"
                        b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # GIT: pack-*.rev
            (b"RIDX\x00\x00\x00", None),
            # RIVE https://rive.app/docs/runtimes/advanced-topic/format
            (b"RIVE", re.compile(b"RIVE[\x06\x07][\x00-\x1F]")),
            # rar v1 and v5
            (b"Rar!\x1A\x07", re.compile(b"Rar!\x1A\x07(\x00|\x01\x00)"))
        ],
        0x54: [
            # timezone info rfc9636
            (b"TZif", re.compile(b"TZif[\x00234]\x00{3}")),
        ],
        0x56: [
            # SVM Metafile
            (b"VCLMTF\x01\x00", None),
        ],
        0x58: [
            # https://www-archive.mozilla.org/scriptable/typelib_file
            (b"XPCOM\nTypeLib\r\n\x1A", None),
            # Macromedia
            (b"XFIR",
             re.compile(b"XFIR[\x00-\xFF]{4}[ 0-9A-Za-z]{4}"
                        b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        0x5A: [
            # .swf with LZMA compression
            (b"ZWS",
             re.compile(b"ZWS[\x0D-\x2B][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
        ],
        0x66: [
            # mp4
            (b"ftyp",
             re.compile(b"ftyp(isom|MSNV)[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # FLAC magic number and seven used types https://www.rfc-editor.org/info/rfc9639/#metadata-block-header
            (b"fLaC", re.compile(b"fLaC[\x00-\x06]")),
        ],
        0x67: [
            # gimp
            (b"gimp xcf",
             re.compile(b"gimp xcf (file|v001|v002)\x00"
                        b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#glb-file-format-specification
            (b"glTF\x02\x00\x00\x00", None),
        ],
        0x69: [
            # icon image up to 24Mb
            (b"icns\x00",
             re.compile(b"icns\x00[\x00-\xFF]{3}"
                        b"(IC(ON|N#)|ic([hms][#48]|s[bB]|l[48]|p[456]|0[45789]|1[0-4])"
                        b"|is32|s8mk|il32|l8mk|ih32|h8mk|it32|t8mk|sb24|SB24)")),
        ],
        0x74: [
            # TrueType Collection v1
            (b"ttcf\x00\x01\x00\x00", None),
            # TrueType Collection v2
            (b"ttcf\x00\x02\x00\x00", None),
        ],
        0x77: [
            # WOFF 1.0, 2.0
            (b"wOF", re.compile(b"wOF[2F][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            # WavPack 4 & 5
            (b"wvpk", re.compile(b"wvpk[\x00-\xFF]{4}[\x02-\x10]\x04")),
        ],
        0x78: [
            # xar v1
            (b"xar!", re.compile(b"xar![\x00-\xFF]{2}\x00\x01")),
        ],
        0x7F: [
            # ELF signature - to quick pass for strings scanner
            (b"\x7FELF", re.compile(b"\x7FELF[\x01\x02][\x01\x02]\x01[\x00-\x12\x40-\xFF]"))
        ],
        0x89: [
            # PNG - can store text chunks inside
            (b"\x89PNG\x0D\x0A\x1A\x0A", None),
            # HDF5
            (b"\x89HDF\r\n\x1a\n", None),
        ],
        0x93: [
            # NUMPY
            (b"\x93NUMPY", None),
        ],
        #
        0xAB: [
            # https://github.khronos.org/KTX-Specification/ktxspec.v2.html
            (b"\xABKTX ", re.compile(b"\xABKTX [\x30-\x39]{2}\xBB\x0D\x0A\x1A\x0A")),
        ],
        0xAC: [
            # Serialized Java Data
            (b"\xAC\xED\x00\x05[\x70-\x7E]", None),
        ],
        0xCE: [
            # Mach-O Executable (reverse 32 bit)
            (b"\xCE\xFA\xED\xFE", None),
        ],
        0xCF: [
            # Mach-O Executable (reverse 64 bit)
            (b"\xCF\xFA\xED\xFE", None),
        ],
        0xD0: [
            # D00DFEED
            (b"\xD0\x0D\xFE\xED", None),
        ],
        0xDE: [
            # GNU MO
            (b"\xDE\x12\x04\x95", None),
        ],
        0xFE: [
            # Mach-O Executable (32 bit)
            (b"\xFE\xED\xFA\xCE", None),
            # Mach-O Executable (64 bit)
            (b"\xFE\xED\xFA\xCF", None),
        ],
        0xFF: [
            # JPEG or MPEG-1 Layer 3
            (b"\xFF", re.compile(b"\xFF(\xD8\xFF[\xDB\xEE\xE1\xE0\x51]|[\xFB\xF3\xF2])")),
            # GIT: Version 2 pack-*.idx
            (b"\xFFtOc\x00\x00\x00", None),
        ]
    }

    @staticmethod
    def detect(data: bytes | bytearray) -> bool:
        """Returns True if well-known media format detected with prefix match approach"""
        if patterns := MagicDetector.MAGIC_PATTERNS.get(data[0]):
            # first byte indexer
            for prefix, pattern in patterns:
                # use prefix magic approach always
                if data.startswith(prefix) and (pattern is None or pattern.match(data)):
                    return True
        return False
