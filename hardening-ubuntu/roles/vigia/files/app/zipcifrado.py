"""ZIP cifrado con contraseña (PKWARE "ZipCrypto"), solo librería estándar.
Es el formato estándar para compartir malware ("infected"): 7-Zip, unzip, ANY.RUN, Triage y
MalwareBazaar lo abren, y evita que un antivirus o un doble clic lo ejecute por accidente.
No es cifrado fuerte (no protege un secreto): su función es que la muestra quede INERTE."""
import secrets, struct, time, zlib

_TABLA = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if _c & 1 else (_c >> 1)
    _TABLA.append(_c)


def zip_cifrado(nombre: str, datos: bytes, clave: bytes = b"infected") -> bytes:
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    T = _TABLA

    def act(c, k0, k1, k2):
        k0 = T[(k0 ^ c) & 0xFF] ^ (k0 >> 8)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = T[(k2 ^ (k1 >> 24)) & 0xFF] ^ (k2 >> 8)
        return k0, k1, k2

    for c in clave:
        k0, k1, k2 = act(c, k0, k1, k2)
    crc = zlib.crc32(datos) & 0xFFFFFFFF
    plano = secrets.token_bytes(11) + bytes([crc >> 24]) + datos
    cif = bytearray(len(plano))
    for i, b in enumerate(plano):
        t = (k2 | 2) & 0xFFFF
        cif[i] = b ^ (((t * (t ^ 1)) >> 8) & 0xFF)
        k0 = T[(k0 ^ b) & 0xFF] ^ (k0 >> 8)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = T[(k2 ^ (k1 >> 24)) & 0xFF] ^ (k2 >> 8)
    lt = time.localtime()
    hora = (lt.tm_hour << 11) | (lt.tm_min << 5) | (lt.tm_sec // 2)
    fecha = ((lt.tm_year - 1980) << 9) | (lt.tm_mon << 5) | lt.tm_mday
    n = nombre.encode()
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, 0, hora, fecha, crc, len(cif), len(datos), len(n), 0) + n
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 0, hora, fecha, crc, len(cif), len(datos),
                          len(n), 0, 0, 0, 0, 0, 0) + n
    fin = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local) + len(cif), 0)
    return local + bytes(cif) + central + fin
