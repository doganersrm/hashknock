HASH KNOCK; siber güvenlik uzmanları, penetration tester’lar ve CTF için geliştirilmiş gelişmiş bir **hash tanımlama aracıdır**.  
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
```bash
git clone https://github.com/doganersrm/hashknock.git

cd hashknock

python3 hashknock.py
```

Tek Hash Analizi
```bash
python3 hashknock.py -h "5f4dcc3b5aa765d61d8327deb882cf99"
```

(Geliştirilecek) Etkileşim Mod
Tekrarlı hash test etmek için.
```bash
python3 hashknock.py
  hashknock> <hashdeğeriyazılır>
```

## HASH KNOCK — Kali Linux Global Kurulum

1) Repo'yu Downloads'a indirdin
 ```bash
~/Downloads/hashknock
````

2) Downloads dizinine geç
```bash
cd ~/Downloads
```
3) Klasörü /opt içine taşı
```bash
sudo mv hashknock /opt/hashknock
```
/opt özel araçların kalıcı dizinidir.
hashcat, msf, burp vb. de buraya kurulur.

4) Ana Python dosyasını çalıştırılabilir yap
```bash
sudo chmod +x /opt/hashknock/hashknock.py
```
5) Global komut wrapper’ı oluştur
```bash
sudo nano /usr/local/bin/hashknock
```
6) Açılan dosyaya şu içeriği yapıştır:
```bash
#!/bin/bash
# HASH KNOCK global komut wrapper'ı
cd /opt/hashknock
exec python3 hashknock.py "$@"
```

Kaydet: CTRL + O, Enter
Çık: CTRL + X

7) Wrapper script’i çalıştırılabilir yap
```bash
sudo chmod +x /usr/local/bin/hashknock
```

Kurulum sonrası 
##v0.5 ile birlikte otomatik güncelleme eklendi.
```bash
hashknock --update 
```

Eğer değiştirilmiş bir yapı kullanıyor ve en güncel sürüme gitmek isterseniz.
```bash
cd /opt/hashknock
sudo git reset --hard
sudo git pull
```

