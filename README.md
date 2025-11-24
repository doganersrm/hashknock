HASH KNOCK; siber güvenlik uzmanları, penetration tester’lar ve CTF oyuncuları için geliştirilmiş gelişmiş bir **hash tanımlama aracıdır**.  
Tamamen **offline çalışır**, JSON tabanlı imza sistemi sayesinde kolayca genişletilebilir ve Hashcat mode numaralarıyla birlikte olasılık yüzdeleri verir.

<img width="981" height="217" alt="image" src="https://github.com/user-attachments/assets/d3c6b8d2-bc78-4e92-b39e-2ad8cf555c59" />

## Özellikler

-  **Hash türü tanıma** (MD5, SHA ailesi, bcrypt, phpass, NTLM, vb…)
-  **Olasılık hesaplama** (% değerleri ile en muhtemel formatları gösterir)
-  **Genişletilebilir signature yapısı** (signatures.json)
-  **Hashcat mode eşleştirme** (hashcat_modes.json)
-  **Tamamen offline çalışma desteği**
-  **CLI arayüz** + etkileşimli `hashknock>` modu
-  Windows CMD tırnak hatalarını otomatik düzeltme
-  Çapraz platform: Linux, Windows, macOS

## Kurulum

git clone https://github.com/doganersrm/hashknock.git

cd hashknock

python3 hashknock.py

Tek Hash Analizi
python3 hashknock.py -h "5f4dcc3b5aa765d61d8327deb882cf99"

(Geliştirilecek) Etkileşim Mod
Tekrarlı hash test etmek için.
python3 hashknock.py
  hashknock> <hashdeğeriyazılır>





