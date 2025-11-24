#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path
from typing import List, Dict, Any


def print_banner():
    banner = r"""
██╗  ██╗ █████╗ ███████╗██╗  ██╗     ██╗  ██╗███   ██╗ ██████╗  ██████╗██╗  ██╗
██║  ██║██╔══██╗██╔════╝██║  ██╝     ██║ ██╔╝████╗ ██║██╔═══██╗██╔════╝██║ ██╔╝
███████║███████║███████╗███████╝     █████╔╝ ██╔██╗██║██║   ██║██║     █████╔╝ 
██╔══██║██╔══██║╚════██║██╔═ ██╗     ██╔═██╗ ██║╚████║██║   ██║██║     ██╔═██╗ 
██║  ██║██║  ██║███████║██║  ██╗     ██║  ██╗██║ ╚███║╚██████╔╝╚██████╗██║  ██╗
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚══╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝

                     HASH KNOCK  —  Hash Type Identifier v0.2
    """
    print(banner)


def is_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))

def print_table(rows, headers):
    """Basit hizalı tablo yazdırır."""
    # Kolon genişliklerini hesapla
    col_widths = [
        max(len(str(row[i])) for row in rows + [headers])
        for i in range(len(headers))
    ]

    # Format string
    fmt = " | ".join("{:<" + str(w) + "}" for w in col_widths)

    # Ayraç
    separator = "-+-".join("-" * w for w in col_widths)

    # Başlık
    print(fmt.format(*headers))
    print(separator)

    # Satırlar
    for row in rows:
        print(fmt.format(*row))
    print()


def load_signatures(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"İmza dosyası bulunamadı: {path}")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    for sig in data:
        pattern = sig.get("regex")
        if not pattern:
            raise ValueError(f"İmzada 'regex' alanı eksik: {sig}")
        sig["_compiled"] = re.compile(pattern)
    return data


def load_hashcat_map(path: Path) -> Dict[str, List[int]]:
    """
    hashcat_modes.json dosyasını okur.
    Yapı:
    {
      "MD5": [0],
      "NTLM": [1000]
    }
    """
    if not path.is_file():
        # Dosya yoksa sessizce boş map döndür.
        return {}
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    mapping: Dict[str, List[int]] = {}
    for key, value in raw.items():
        if isinstance(value, list):
            mapping[key] = [int(v) for v in value]
        else:
            mapping[key] = [int(value)]
    return mapping


def identify_hash(hash_value: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    h = hash_value.strip()
    matches: List[Dict[str, Any]] = []

    for sig in signatures:
        if sig["_compiled"].fullmatch(h):
            matches.append(sig)

    # Hex ise ve birden çok eşleşme varsa Generic Base64 gibi çok genel olanları ele
    if is_hex(h) and len(matches) > 1:
        filtered = [
            m for m in matches
            if "Generic Base64" not in m.get("name", "")
        ]
        if filtered:
            matches = filtered

    return matches


def compute_probabilities(matches: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Basit ağırlıklandırma:
      - Generic Base64 gibi genel imzalar: 1
      - Diğerleri: 3
    """
    weights = []
    for m in matches:
        name = m.get("name", "")
        if "Generic Base64" in name:
            w = 1
        else:
            w = 3
        weights.append(w)

    total = sum(weights) or 1
    probs: Dict[str, float] = {}
    for m, w in zip(matches, weights):
        name = m.get("name", "Bilinmeyen")
        probs[name] = round((w / total) * 100, 2)

    return probs


def analyze_and_print(hash_value: str,
                      signatures: List[Dict[str, Any]],
                      hashcat_map: Dict[str, List[int]]) -> None:
    """Tek bir hash için analizi yapıp ekrana basar."""
    # Windows CMD tek/çift tırnak düzeltmesi
    raw = hash_value.strip()
    if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
        h = raw[1:-1]
    else:
        h = raw

    print(f"[+] Girdiğin hash:\n    {h}\n")

    matches = identify_hash(h, signatures)

    if not matches:
        print("[-] Bu hash için tanımlı bir imza bulunamadı.")
        print("[*] Yeni bir hash tipi gördüysen, signatures.json'a yeni regex imzası ekleyebilirsin.\n")
        return

    probs = compute_probabilities(matches)

    print("\n[+] Eşleşen muhtemel hash türleri:\n")

    rows = []
    for sig in matches:
        name = sig.get("name", "Bilinmeyen")
        desc = sig.get("description", "")
        p = f"%{probs.get(name, 0.0)}"

        hashcat_key = sig.get("hashcat_key") or name
        modes = hashcat_map.get(hashcat_key)
        mode_str = ", ".join(str(m) for m in modes) if modes else "-"

        rows.append([name, desc, p, mode_str])

    print_table(
        rows,
        headers=["Hash Türü", "Açıklama", "Olasılık", "Hashcat Mode"]
    )


    print("[*] Not: Birden fazla eşleşme olması normaldir; bazı formatlar aynı pattern'i paylaşır.")
    print("[*] Hashcat mod bilgisi sadece referans içindir; cracking işlemini ayrıca Hashcat ile yapman gerekir.\n")


def main():
    parser = argparse.ArgumentParser(
        prog="hashknock",
        description="Hash Tanıma Aracı (JSON imzalı, % olasılık + Hashcat mode gösterir).",
        add_help=False
    )

    # Senin isteğin: -h ile hash girilsin
    parser.add_argument(
        "-h", "--hash",
        dest="hash_value",
        help="Türü tahmin edilecek hash değeri (tırnaklı/çıplak yazabilirsin)."
    )
    parser.add_argument(
        "-s", "--signatures",
        default="signatures.json",
        help="İmza dosyası (varsayılan: signatures.json)"
    )
    parser.add_argument(
        "-m", "--hashcat-modes",
        default="hashcat_modes.json",
        help="Hashcat mode eşlemesi dosyası (varsayılan: hashcat_modes.json)"
    )
    parser.add_argument(
        "-H", "--help",
        action="help",
        help="Bu yardım mesajını göster ve çık."
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version="hashknock 1.0",
        help="Sürüm bilgisini göster."
    )

    args = parser.parse_args()

    print_banner()

    sig_path = Path(args.signatures)
    modes_path = Path(args.hashcat_modes)

    try:
        signatures = load_signatures(sig_path)
    except Exception as e:
        print(f"[-] İmza dosyası yüklenemedi: {e}")
        return

    hashcat_map = load_hashcat_map(modes_path)

    # Eğer -h/--hash ile hash verildiyse tek seferlik çalış
    if args.hash_value:
        analyze_and_print(args.hash_value, signatures, hashcat_map)
        return

    # Hiç argüman yoksa: etkileşimli mod
    print("[*] Komut satırında hash vermedin. Etkileşimli moda geçiliyor.")
    print("[*] Çıkmak için 'exit', 'quit' veya Ctrl+C kullanabilirsin.\n")

    while True:
        try:
            line = input("hashknock> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[+] Çıkılıyor.")
            break

        if not line:
            continue
        if line.lower() in ("exit", "quit", "q"):
            print("[+] Çıkılıyor.")
            break

        analyze_and_print(line, signatures, hashcat_map)


if __name__ == "__main__":
    main()
