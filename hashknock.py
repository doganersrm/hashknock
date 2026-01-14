#!/usr/bin/env python3
import argparse
import json
import re
import os
import subprocess
import sys
import csv
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

# Renkli çıktı için basit ANSI kodları
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Renklendirme aktif mi (--no-color ile kapatılabilir)
USE_COLOR = True

def colored(text: str, color: str) -> str:
    """Metni renklendirir (eğer USE_COLOR True ise)"""
    if USE_COLOR:
        return f"{color}{text}{Colors.ENDC}"
    return text


def print_banner():
    banner = r"""
██╗  ██╗ █████╗ ███████╗██╗  ██╗     ██╗  ██╗███   ██╗ ██████╗  ██████╗██╗  ██╗
██║  ██║██╔══██╗██╔════╝██║  ██╝     ██║ ██╔╝████╗ ██║██╔═══██╗██╔════╝██║ ██╔╝
███████║███████║███████╗███████╝     █████╔╝ ██╔██╗██║██║   ██║██║     █████╔╝ 
██╔══██║██╔══██║╚════██║██╔═ ██╗     ██╔═██╗ ██║╚████║██║   ██║██║     ██╔═██╗ 
██║  ██║██║  ██║███████║██║  ██╗     ██║  ██╗██║ ╚███║╚██████╔╝╚██████╗██║  ██╗
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚══╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝

                     HASH KNOCK  —  Hash Type Identifier v2.0
    """
    print(colored(banner, Colors.HEADER))


def is_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def print_table(rows, headers):
    """Basit hizalı tablo yazdırır."""
    if not rows:
        return
    
    col_widths = [
        max(len(str(row[i])) for row in rows + [headers])
        for i in range(len(headers))
    ]
    fmt = " | ".join(f"{{:<{w}}}" for w in col_widths)
    separator = "-+-".join("-" * w for w in col_widths)

    print(colored(fmt.format(*headers), Colors.BOLD))
    print(separator)

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
        try:
            sig["_compiled"] = re.compile(pattern)
        except re.error as e:
            print(colored(f"[!] Regex hatası '{pattern}': {e}", Colors.WARNING))
            continue
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


def detect_salt(hash_value: str) -> Tuple[str, Optional[str]]:
    """
    Hash içinde salt varsa ayırır.
    Formatlar: hash:salt, $algo$salt$hash vb.
    
    Returns:
        (hash_part, salt_part or None)
    """
    # Format 1: hash:salt (basit)
    if ":" in hash_value and not hash_value.startswith("$"):
        parts = hash_value.split(":", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
    
    # Format 2: $algo$salt$hash (örn: bcrypt, sha512crypt)
    if hash_value.startswith("$"):
        parts = hash_value.split("$")
        if len(parts) >= 4:
            # Genelde $algo$rounds/salt$hash formatı
            # Salt genellikle 3. alandadır
            salt_candidate = parts[2] if len(parts) > 2 else None
            if salt_candidate and len(salt_candidate) > 0:
                return hash_value, salt_candidate
    
    return hash_value, None


def identify_hash(hash_value: str, signatures: List[Dict[str, Any]], verbose: bool = False) -> List[Dict[str, Any]]:
    h = hash_value.strip()
    matches: List[Dict[str, Any]] = []

    for sig in signatures:
        if "_compiled" not in sig:
            continue
        try:
            if sig["_compiled"].fullmatch(h):
                matches.append(sig)
                if verbose:
                    print(colored(f"  ✓ Eşleşti: {sig.get('name', 'Unknown')}", Colors.OKGREEN))
        except Exception as e:
            if verbose:
                print(colored(f"  ✗ Regex hatası: {e}", Colors.FAIL))
            continue

    # Hex ise ve birden çok eşleşme varsa Generic Base64 gibi çok genel olanları filtrele
    if is_hex(h) and len(matches) > 1:
        filtered = [
            m for m in matches
            if "Generic Base64" not in m.get("name", "") and "base64" not in m.get("name", "").lower()
        ]
        if filtered:
            if verbose:
                print(colored(f"  [*] Generic/Base64 türleri filtrelendi, kalan: {len(filtered)}", Colors.OKCYAN))
            matches = filtered

    # Uzunluk bazlı önceliklendirme (daha spesifik olanlar önce)
    matches.sort(key=lambda m: len(m.get("name", "")), reverse=True)

    return matches


def compute_probabilities(matches: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Basit ağırlıklandırma:
      - Generic Base64 gibi genel imzalar: 1
      - Veritabanı spesifik (MySQL, PostgreSQL, MSSQL, Oracle): 5
      - Framework spesifik (Django, WordPress, Joomla): 4
      - Standart hash'ler (MD5, SHA, NTLM): 3
    """
    weights = []
    for m in matches:
        name = m.get("name", "").lower()
        
        # Generic/Base64
        if "generic" in name or "base64" in name:
            w = 1
        # Veritabanı spesifik
        elif any(db in name for db in ["mysql", "postgresql", "mssql", "oracle", "mongo"]):
            w = 5
        # Framework spesifik
        elif any(fw in name for fw in ["django", "wordpress", "joomla", "drupal", "phpbb", "vbulletin"]):
            w = 4
        # Cisco, LDAP gibi özel formatlar
        elif any(spec in name for spec in ["cisco", "ldap", "wpa", "argon"]):
            w = 4
        # Standart hash'ler
        else:
            w = 3
        
        weights.append(w)

    total = sum(weights) or 1
    probs: Dict[str, float] = {}
    for m, w in zip(matches, weights):
        name = m.get("name", "Bilinmeyen")
        probs[name] = round((w / total) * 100, 2)

    return probs


def generate_hashcat_command(hash_value: str, 
                            matches: List[Dict[str, Any]], 
                            hashcat_map: Dict[str, List[int]],
                            verbose: bool = False) -> List[str]:
    """
    En olası hash türlerine göre hashcat komutları oluşturur.
    Birden fazla komut dönebilir.
    """
    if not matches:
        return []
    
    # Olasılıklara göre sırala
    probs = compute_probabilities(matches)
    sorted_matches = sorted(matches, key=lambda m: probs.get(m.get("name", ""), 0), reverse=True)
    
    commands = []
    seen_modes = set()
    
    # En yüksek 3 olasılığı al
    for match in sorted_matches[:3]:
        name = match.get("name", "")
        hashcat_key = match.get("hashcat_key") or name
        modes = hashcat_map.get(hashcat_key, [])
        
        if not modes:
            if verbose:
                print(colored(f"[!] '{name}' için hashcat mode bulunamadı.", Colors.WARNING))
            continue
        
        for mode in modes:
            if mode not in seen_modes:
                seen_modes.add(mode)
                prob = probs.get(name, 0)
                cmd = f"hashcat -m {mode} -a 0 hash.txt wordlist.txt  # {name} (%{prob})"
                commands.append(cmd)
    
    return commands


def analyze_hash(hash_value: str,
                signatures: List[Dict[str, Any]],
                hashcat_map: Dict[str, List[int]],
                verbose: bool = False) -> Dict[str, Any]:
    """
    Tek bir hash için analiz yapar ve sonuçları dict olarak döner.
    """
    raw = hash_value.strip()
    if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
        h = raw[1:-1]
    else:
        h = raw

    # Salt tespiti
    hash_part, salt_part = detect_salt(h)
    
    if verbose and salt_part:
        print(colored(f"[*] Salt tespit edildi: {salt_part}", Colors.OKCYAN))

    matches = identify_hash(h, signatures, verbose)
    
    result = {
        "original_hash": h,
        "hash_part": hash_part,
        "salt": salt_part,
        "hash_length": len(h),
        "matches": [],
        "hashcat_commands": []
    }

    if not matches:
        result["status"] = "no_match"
        return result

    result["status"] = "success"
    probs = compute_probabilities(matches)

    for sig in matches:
        name = sig.get("name", "Bilinmeyen")
        desc = sig.get("description", "")
        prob = probs.get(name, 0.0)

        hashcat_key = sig.get("hashcat_key") or name
        modes = hashcat_map.get(hashcat_key, [])
        mode_str = ", ".join(str(m) for m in modes) if modes else "-"

        result["matches"].append({
            "name": name,
            "description": desc,
            "probability": prob,
            "hashcat_modes": mode_str
        })

    # Hashcat komutları oluştur
    hashcat_cmds = generate_hashcat_command(h, matches, hashcat_map, verbose)
    if hashcat_cmds:
        result["hashcat_commands"] = hashcat_cmds

    return result


def analyze_and_print(hash_value: str,
                      signatures: List[Dict[str, Any]],
                      hashcat_map: Dict[str, List[int]],
                      verbose: bool = False) -> Dict[str, Any]:
    """Tek bir hash için analizi yapıp ekrana basar."""
    
    result = analyze_hash(hash_value, signatures, hashcat_map, verbose)
    
    print(colored(f"[+] Hash:", Colors.OKGREEN))
    print(f"    {result['original_hash']}")
    print(colored(f"[+] Uzunluk:", Colors.OKBLUE))
    print(f"    {result['hash_length']} karakter\n")
    
    if result.get("salt"):
        print(colored(f"[+] Salt tespit edildi:", Colors.WARNING))
        print(f"    {result['salt']}\n")

    if result["status"] == "no_match":
        print(colored("[-] Bu hash için tanımlı bir imza bulunamadı.", Colors.FAIL))
        print(colored("[*] Yeni bir hash tipi gördüysen, signatures.json'a yeni regex imzası ekleyebilirsin.\n", Colors.WARNING))
        return result

    print(colored(f"[+] {len(result['matches'])} olası hash türü bulundu:\n", Colors.OKGREEN))

    rows = []
    for match in result["matches"]:
        prob = match['probability']
        # Olasılığa göre renklendirme
        if prob >= 20:
            prob_colored = colored(f"%{prob}", Colors.OKGREEN)
        elif prob >= 10:
            prob_colored = colored(f"%{prob}", Colors.WARNING)
        else:
            prob_colored = f"%{prob}"
        
        rows.append([
            match["name"],
            match["description"][:60] + "..." if len(match["description"]) > 60 else match["description"],
            prob_colored,
            match["hashcat_modes"]
        ])

    print_table(
        rows,
        headers=["Hash Türü", "Açıklama", "Olasılık", "Hashcat Mode"]
    )

    if result.get("hashcat_commands"):
        print(colored("[+] Önerilen Hashcat Komutları:\n", Colors.OKGREEN))
        for idx, cmd in enumerate(result["hashcat_commands"], 1):
            print(colored(f"  {idx}. {cmd}", Colors.OKCYAN))
        print()

    print(colored("[*] Not: Birden fazla eşleşme normaldir; bazı formatlar aynı uzunluğu paylaşır.", Colors.WARNING))
    print(colored("[*] Hash'i 'hash.txt' dosyasına kaydet ve yukarıdaki komutları dene.\n", Colors.WARNING))
    
    return result


def analyze_file(file_path: Path,
                signatures: List[Dict[str, Any]],
                hashcat_map: Dict[str, List[int]],
                verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Dosyadan hash'leri okur ve analiz eder.
    """
    if not file_path.is_file():
        print(colored(f"[-] Dosya bulunamadı: {file_path}", Colors.FAIL))
        return []
    
    results = []
    
    with file_path.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    total = len(lines)
    print(colored(f"[+] Dosyadan {total} hash okundu. Analiz başlıyor...\n", Colors.OKGREEN))
    
    for idx, line in enumerate(lines, 1):
        if verbose:
            print(colored(f"\n{'='*70}", Colors.BOLD))
            print(colored(f"[*] İşleniyor ({idx}/{total}): {line[:50]}...", Colors.OKCYAN))
        
        result = analyze_hash(line, signatures, hashcat_map, verbose)
        results.append(result)
        
        if not verbose:
            # Kısa progress gösterimi
            if result["status"] == "success":
                print(colored(f"  [{idx}/{total}] ✓ {line[:40]}... → {result['matches'][0]['name']}", Colors.OKGREEN))
            else:
                print(colored(f"  [{idx}/{total}] ✗ {line[:40]}... → No match", Colors.FAIL))
    
    print(colored(f"\n[+] Toplam {total} hash analiz edildi.\n", Colors.OKGREEN))
    
    # Özet istatistik
    success_count = sum(1 for r in results if r["status"] == "success")
    print(colored(f"[+] Başarılı: {success_count}, Eşleşmedi: {total - success_count}", Colors.OKCYAN))
    
    return results


def output_json(results: List[Dict[str, Any]], output_file: Optional[str] = None):
    """Sonuçları JSON formatında çıktı verir."""
    # _compiled regex objelerini kaldır
    clean_results = []
    for r in results:
        clean_r = {k: v for k, v in r.items() if not k.startswith("_")}
        if "matches" in clean_r:
            clean_r["matches"] = [
                {k: v for k, v in m.items() if not k.startswith("_")}
                for m in clean_r["matches"]
            ]
        clean_results.append(clean_r)
    
    json_output = json.dumps(clean_results, indent=2, ensure_ascii=False)
    
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(json_output)
        print(colored(f"[+] JSON çıktısı kaydedildi: {output_file}", Colors.OKGREEN))
    else:
        print(json_output)


def output_csv(results: List[Dict[str, Any]], output_file: Optional[str] = None):
    """Sonuçları CSV formatında çıktı verir."""
    rows = []
    
    for r in results:
        base = {
            "hash": r["original_hash"],
            "length": r.get("hash_length", 0),
            "salt": r.get("salt", ""),
            "status": r["status"]
        }
        
        if r["status"] == "success" and r["matches"]:
            for match in r["matches"]:
                row = base.copy()
                row.update({
                    "hash_type": match["name"],
                    "description": match["description"],
                    "probability": match["probability"],
                    "hashcat_modes": match["hashcat_modes"]
                })
                rows.append(row)
        else:
            base.update({
                "hash_type": "No Match",
                "description": "",
                "probability": 0,
                "hashcat_modes": ""
            })
            rows.append(base)
    
    if not rows:
        return
    
    fieldnames = ["hash", "length", "salt", "status", "hash_type", "description", "probability", "hashcat_modes"]
    
    if output_file:
        with open(output_file, "w", encoding="utf-8", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(colored(f"[+] CSV çıktısı kaydedildi: {output_file}", Colors.OKGREEN))
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def update_hashknock():
    """
    /opt/hashknock altında git pull ile güncelleme yapar.
    'hashknock --update' ile çağrılır.
    """
    print(colored("[*] HASH KNOCK: Güncelleme başlatılıyor...\n", Colors.OKCYAN))

    repo_url = "https://github.com/doganersrm/hashknock.git"
    install_dir = "/opt/hashknock"

    if not os.path.exists(install_dir):
        print(colored(f"[-] {install_dir} dizini bulunamadı.", Colors.FAIL))
        print("[*] Bu komut, aracı /opt/hashknock altına git clone ile kurduğunu varsayar.")
        print(f"[*] İlk kurulum için örnek:")
        print(f"    sudo git clone {repo_url} {install_dir}\n")
        sys.exit(1)

    # git var mı kontrolü
    try:
        subprocess.run(["git", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print(colored("[-] 'git' komutu bulunamadı. Lütfen önce git kur:", Colors.FAIL))
        print("    sudo apt install git\n")
        sys.exit(1)

    try:
        print(colored(f"[*] {install_dir} dizininde 'git pull' çalıştırılıyor...\n", Colors.OKCYAN))
        subprocess.run(["sudo", "git", "-C", install_dir, "pull"], check=True)
        print(colored("\n[+] HASH KNOCK başarıyla güncellendi!", Colors.OKGREEN))
        print(colored("[*] Değişikliklerin etkili olması için komutu yeniden çalıştırabilirsin.\n", Colors.OKCYAN))
        sys.exit(0)
    except subprocess.CalledProcessError:
        print(colored("[-] 'git pull' sırasında bir hata oluştu. Lütfen dizinin bir git repo olduğundan emin ol.", Colors.FAIL))
        sys.exit(1)


def main():
    global USE_COLOR
    
    parser = argparse.ArgumentParser(
        prog="hashknock",
        description="Hash Tanıma Aracı v2.0 (Toplu analiz, JSON/CSV çıktı, Hashcat komut oluşturma, Salt tespiti)",
        add_help=False
    )

    # Temel parametreler
    parser.add_argument(
        "-h", "--hash",
        dest="hash_value",
        help="Türü tahmin edilecek hash değeri"
    )
    parser.add_argument(
        "-f", "--file",
        dest="hash_file",
        help="Hash'lerin bulunduğu dosya (her satırda bir hash)"
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
    
    # Çıktı formatı
    parser.add_argument(
        "-o", "--output",
        choices=["json", "csv"],
        help="Çıktı formatı (json veya csv)"
    )
    parser.add_argument(
        "--output-file",
        help="Çıktının kaydedileceği dosya (belirtilmezse stdout'a yazar)"
    )
    
    # Diğer özellikler
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Detaylı çıktı (debug modu)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Renkli çıktıyı devre dışı bırak"
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="HASH KNOCK aracını /opt/hashknock altında git pull ile günceller"
    )
    parser.add_argument(
        "-H", "--help",
        action="help",
        help="Bu yardım mesajını göster ve çık"
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version="hashknock 2.0",
        help="Sürüm bilgisini göster"
    )

    args = parser.parse_args()

    # Renk ayarı
    if args.no_color:
        USE_COLOR = False

    # Update isteği
    if args.update:
        update_hashknock()

    print_banner()

    sig_path = Path(args.signatures)
    modes_path = Path(args.hashcat_modes)

    try:
        signatures = load_signatures(sig_path)
        if args.verbose:
            print(colored(f"[*] {len(signatures)} imza yüklendi.", Colors.OKCYAN))
    except Exception as e:
        print(colored(f"[-] İmza dosyası yüklenemedi: {e}", Colors.FAIL))
        print(colored(f"[*] Dosya yolu: {sig_path.absolute()}", Colors.WARNING))
        return

    hashcat_map = load_hashcat_map(modes_path)
    if args.verbose and hashcat_map:
        print(colored(f"[*] {len(hashcat_map)} hashcat mode eşlemesi yüklendi.\n", Colors.OKCYAN))
    elif not hashcat_map:
        print(colored(f"[!] Hashcat mode dosyası yüklenemedi: {modes_path}", Colors.WARNING))
        print(colored("[*] Mode numaraları gösterilmeyecek.\n", Colors.WARNING))

    # Dosyadan toplu analiz
    if args.hash_file:
        results = analyze_file(Path(args.hash_file), signatures, hashcat_map, args.verbose)
        
        if args.output == "json":
            output_json(results, args.output_file)
        elif args.output == "csv":
            output_csv(results, args.output_file)
        else:
            # Normal çıktıda özet istatistik
            if not args.verbose:
                print(colored("\n[+] En çok bulunan hash türleri:", Colors.OKGREEN))
                type_counts = {}
                for r in results:
                    if r["status"] == "success" and r["matches"]:
                        top_match = r["matches"][0]["name"]
                        type_counts[top_match] = type_counts.get(top_match, 0) + 1
                
                sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
                for hash_type, count in sorted_types[:10]:
                    print(f"  • {hash_type}: {count} adet")
                print()
        return

    # Tek hash analizi
    if args.hash_value:
        result = analyze_and_print(args.hash_value, signatures, hashcat_map, args.verbose)
        
        if args.output == "json":
            output_json([result], args.output_file)
        elif args.output == "csv":
            output_csv([result], args.output_file)
        return

    # Etkileşimli mod
    print(colored("[*] Komut satırında hash vermedin. Etkileşimli moda geçiliyor.", Colors.OKCYAN))
    print(colored("[*] Çıkmak için 'exit', 'quit' veya Ctrl+C kullanabilirsin.\n", Colors.WARNING))

    while True:
        try:
            line = input(colored("hashknock> ", Colors.OKBLUE)).strip()
        except (EOFError, KeyboardInterrupt):
            print(colored("\n[+] Çıkılıyor.", Colors.OKGREEN))
            break

        if not line:
            continue
        if line.lower() in ("exit", "quit", "q"):
            print(colored("[+] Çıkılıyor.", Colors.OKGREEN))
            break

        analyze_and_print(line, signatures, hashcat_map, args.verbose)


if __name__ == "__main__":
    main()
