import re


class MagicDetector:
    """Detect known binary file formats using signatures at predefined offsets.

    Each signature consists of a byte prefix and an optional regular expression to validate additional data.
    Signatures are indexed by offset and the byte value at that offset for efficient lookup.
    """

    MAGIC_PATTERNS: dict[int, dict[int, list[tuple[bytes, None | re.Pattern]]]] = {
        0: {
            0x00: [
                # JPEG2000
                (b"\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A", None),
                # ICO
                (b"\x00\x00\x01\x00", None),
                # M2V
                (b"\x00\x00\x01\xB3", None),
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
            0x01: [
                # https://fontforge.org/docs/techref/pcf-format.html
                (b"\x01fcp", None),
            ],
            0x02: [
                # Binary CMap
                (b"\x02\xE0RCopyright", None),
            ],
            0x03: [
                # Android Binary XML
                (b"\x03\x00\x08\x00", None),
                # Python 2.7 artifact
                (b"\x03\xf3\r\n", None),
                # SPIR-V Shader Module (.spv)
                (b"\x03\x02#\x07", None),
            ],
            0x0E: [
                # HDF4
                (b"\x0E\x03\x13\x01", None),
            ],
            0x10: [
                # TIM
                (b"\x10\x00\x00\x00", None),
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
                # https://rocm.docs.amd.com/projects/llvm-project/en/latest/LLVM/llvm/html/BitCodeFormat.html
                (b"BC\xC0\xDE", None),
            ],
            0x43: [
                # .swf with ZLIB compression
                (b"CWS",
                 re.compile(b"CWS[\x06-\x2B][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")
                 ),
                # CachedDateTimeZone
                (b"C\x00", re.compile(b"C\x00[\x02-\x0A]\x00[\x03-\x06\x0A][A-Z]{2,4}T[A-Za-z-]*\x00")),
            ],
            0x44: [
                # .dds file
                (b"DDS ", re.compile(b"DDS [^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
            ],
            0x46: [
                # .swf
                (b"FWS",
                 re.compile(b"FWS[\x01-\x2B][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")
                 ),
                # https://grub.gibibit.com/New_font_format
                (b"FILE\x00\x00\x00\x04PFF2", None),
                # FixedDateTimeZone
                (b"F\x00", re.compile(b"F\x00[\x03\x05\x06][A-Z][A-Z][TC]")),
            ],
            0x47: [
                # GIF
                (b"GIF8",
                 re.compile(b"GIF8[79]a[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
                # https://gnome.pages.gitlab.gnome.org/gobject-introspection/girepository/gi-GITypelib-Internals.html
                (b"GOBJ\nMETADATA\r\n\x1a", None),
            ],
            0x49: [
                # TIFF little endian
                (b"II",
                 re.compile(b"II[+*]\x00[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
                # jxr
                (b"II\xBC\x01", None),
                # ID2v3 for various media (e.g. MP3)
                (b"ID3", re.compile(b"ID3[\x02\x03\x04]\x00\x00\x00")),
            ],
            0x4D: [
                # TIFF big endian
                (b"MM",
                 re.compile(b"MM\x00[+*][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
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
                # PrecalculatedDateTimeZone
                (b"P\x00", re.compile(b"P\x00[\x02-\x05]\x00[\x03-\x04][A-Z]{2,4}T\x00")),
                # PKM format for ETC1 texture
                (b"PKM 10\x00\x00", None),
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
                 re.compile(b"ZWS[\x0D-\x2B][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")
                 ),
            ],
            0x66: [
                # mp4
                (b"ftyp",
                 re.compile(b"ftyp(isom|MSNV)[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")
                 ),
                # FLAC magic number and seven used types https://www.rfc-editor.org/info/rfc9639/#metadata-block-header
                (b"fLaC", re.compile(b"fLaC[\x00-\x06]")),
            ],
            0x67: [
                # gimp
                (b"gimp xcf",
                 re.compile(b"gimp xcf (file|v[0-9]{3})\x00"
                            b"[^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")),
                # https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html#glb-file-format-specification
                (b"glTF\x02\x00\x00\x00", None),
                # GD2 images
                (b"gd2\x00\x00", None),
            ],
            0x69: [
                # icon image up to 24Mb
                (b"icns\x00",
                 re.compile(b"icns\x00[\x00-\xFF]{3}"
                            b"(IC(ON|N#)|ic([hms][#48]|s[bB]|l[48]|p[456]|0[45789]|1[0-4])"
                            b"|is32|s8mk|il32|l8mk|ih32|h8mk|it32|t8mk|sb24|SB24)")),
                # Magick Image File Format
                (b"id=ImageMagick",
                 re.compile(b"id=ImageMagick[\x09\x0A\x0D\x20-\x7E\xA0-\xFF]+"
                            b"(columns=[0-9]+[\x09\x0A\x0D\x20-\x7E\xA0-\xFF]+rows=[0-9]+"
                            b"|rows=[0-9]+[\x09\x0A\x0D\x20-\x7E\xA0-\xFF]+columns=[0-9]+)"
                            b"[\x09\x0A\x0D\x20-\x7E\xA0-\xFF]+[\x00-\x08\x0B\x0C\x0E-\x1F\x80-\x8F]")),
            ],
            0x74: [
                # TrueType Collection v1
                (b"ttcf\x00\x01\x00\x00", None),
                # TrueType Collection v2
                (b"ttcf\x00\x02\x00\x00", None),
            ],
            0x77: [
                # WOFF 1.0, 2.0
                (b"wOF", re.compile(b"wOF[2F][^\x00-\x08\x0C\x0E\x1F\x80-\xFF]{0,4096}[\x00-\x08\x0C\x0E\x1F\x80-\xFF]")
                 ),
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
                (b"\x89HDF\r\n\x1A\n", None),
            ],
            0x8B: [
                # JNG
                (b"\x8BJNG\x0D\x0A\x1A\x0A", None),
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
                (b"\xAC\xED\x00\x05", re.compile(b"\xAC\xED\x00\x05[\x70-\x7E]")),
            ],
            0xC5: [
                # DOS EPS Binary File
                (b"\xC5\xD0\xD3\xC6", None),
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
            0xD7: [
                # WMF
                (b"\xD7\xCD\xC6\x9A\x00\x00", None),
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
                # JP2
                (b"\xFFO\xFFQc\x00\x00\x00", None),
                # GIT: Version 2 pack-*.idx
                (b"\xFFtOc\x00\x00\x00", None),
                # https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/ProfileData/InstrProf.h
                (b"\xFFlprofi\x81", None),
            ]
        },
        0x22: {
            0x4C: [
                # EOT format https://www.w3.org/submissions/EOT/
                (b"LP", re.compile(b"[\x00-\xFF]{34}LP[\x00-\xFF]{28}\x00{16}")),
            ],
        },
        0x200: {
            0x89: [
                # HDF5 with offset = 512
                (b"\x89HDF\r\n\x1A\n", None),
            ],
        },
        0x400: {
            0x89: [
                # HDF5 with offset = 1024
                (b"\x89HDF\r\n\x1A\n", None),
            ],
        },
        0x800: {
            0x89: [
                # HDF5 with offset = 2048
                (b"\x89HDF\r\n\x1A\n", None),
            ],
        }
    }

    @staticmethod
    def detect(data: bytes | bytearray) -> bool:
        """Return True if data matches a known binary file signature.

        Checks byte prefixes at predefined offsets and optionally validates the data against a regular expression.
        """
        for offset, detector in MagicDetector.MAGIC_PATTERNS.items():
            if offset < len(data) and (patterns := detector.get(data[offset])):
                for prefix, pattern in patterns:
                    # use prefix magic approach always
                    if data.startswith(prefix, offset) and (pattern is None or pattern.match(data)):
                        return True
        return False
