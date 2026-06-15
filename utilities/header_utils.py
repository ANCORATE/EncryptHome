import struct
import os
import binascii

# === Funktionen für Header-Reparatur & Prüfung ===

def detect_header_state(data: bytes, header_fmt: str, magic: bytes, header_len: int) -> str:
    """
    Prüft, ob und in welchem Zustand der Header existiert.
    Gibt 'none', 'partial' oder 'full' zurück.
    """
    if not data.startswith(magic):
        return "none"
    if len(data) < header_len:
        return "partial"
    try:
        struct.unpack(header_fmt, data[:header_len])
        return "full"
    except struct.error:
        return "partial"


def restore_header(input_path: str, output_path: str, salt: bytes, flags: int,
                   write_header_func, header_fmt: str, magic: bytes, header_len: int):
    """
    Stellt den Header einer Containerdatei wieder her.
    :param input_path: beschädigte Datei
    :param output_path: Zielpfad
    :param salt: Salt bytes
    :param flags: Header-Flags
    :param write_header_func: Funktion, die Header in Datei schreibt
    :param header_fmt: struct Format für Header
    :param magic: Magic Bytes
    :param header_len: Header Länge
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Datei nicht gefunden: {input_path}")

    with open(input_path, "rb") as f:
        data = f.read()

    state = detect_header_state(data, header_fmt, magic, header_len)

    if state == "none":
        print("[Info] Kein Header gefunden – neuer Header wird hinzugefügt.")
        new_data = data
    elif state == "partial":
        print("[Warnung] Partieller Header erkannt – wird ersetzt.")
        start_offset = data.find(magic)
        if start_offset != -1:
            new_data = data[start_offset + len(magic):]
        else:
            new_data = data
    else:
        print("[Info] Vollständiger Header erkannt – wird ersetzt.")
        new_data = data[header_len:]

    with open(output_path, "r+b") as out:
        write_header_func(out, flags, salt)
        out.write(new_data)

    print(f"[OK] Header erfolgreich wiederhergestellt → {output_path}")


def verify_header(path: str, header_fmt: str, magic: bytes, flags_device: int, flags_keyfile: int, header_len: int):
    """
    Liest und überprüft den Header einer Datei.
    Gibt ein Dictionary mit allen Feldern zurück, falls gültig.
    """
    with open(path, "rb") as f:
        header_data = f.read(header_len)

    if len(header_data) < header_len:
        print("[Fehler] Datei zu kurz für vollständigen Header.")
        return None

    try:
        magic_read, version, flags, salt, reserved = struct.unpack(header_fmt, header_data)
    except struct.error:
        print("[Fehler] Header konnte nicht entpackt werden.")
        return None

    if magic_read != magic:
        print(f"[Fehler] Ungültige Magic Bytes: {magic_read!r}")
        return None

    print("[OK] Gültiger Header erkannt.")
    print(f"  Version: {version}")
    print(f"  Flags: {flags:#04x} (DEVICE={bool(flags & flags_device)}, KEYFILE={bool(flags & flags_keyfile)})")
    print(f"  Salt: {binascii.hexlify(salt).decode().upper()}")
    return {
        "magic": magic_read,
        "version": version,
        "flags": flags,
        "salt": salt,
        "reserved": reserved,
    }
