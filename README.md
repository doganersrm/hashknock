HASH KNOCK; siber güvenlik uzmanları, penetration tester’lar ve CTF için geliştirilmiş gelişmiş bir **hash tanımlama aracıdır**.  
Tamamen **offline çalışır**, JSON tabanlı imza sistemi sayesinde kolayca genişletilebilir ve Hashcat mode numaralarıyla birlikte olasılık yüzdeleri verir.

<img width="981" height="217" alt="image" src="https://github.com/user-attachments/assets/982996fa-f006-43eb-b072-30129e9f4972" />


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

## Kurulum sonrası 

#v0.5 ile birlikte otomatik güncelleme eklendi.
```bash
hashknock --update 
```

#Eğer değiştirilmiş bir yapı kullanıyor ve en güncel sürüme gitmek isterseniz.
```bash
cd /opt/hashknock
sudo git reset --hard
sudo git pull
```

---

## Yeni İyileştirmeler (v2.0)

### 1) Gelişmiş Olasılık Hesaplama
HASH KNOCK artık hash türlerini sadece regex eşleşmesine göre değil, **bağlamsal ağırlıklandırma** ile sıralar.

- **Veritabanı spesifik hash'ler** (MySQL, PostgreSQL, MSSQL, Oracle): **%5 ağırlık**
- **Framework spesifik hash'ler** (Django, WordPress, Joomla): **%4 ağırlık**
- **Standart hash'ler** (MD5, SHA, NTLM): **%3 ağırlık**
- **Generic / Base64** türleri: **%1 ağırlık**

 Amaç: Daha **spesifik ve anlamlı** hash formatlarını otomatik olarak üst sıralara taşımak.

### 2) Birden Fazla Hashcat Komutu Üretimi
En olası **ilk 3 hash türü** için otomatik olarak ayrı **Hashcat cracking komutları** oluşturulur.

- Her komutta:
  - Hash türü
  - Olasılık yüzdesi
  - İlgili Hashcat mode numarası
- Kullanıcı doğrudan kopyala-çalıştır yapabilir
- 
```bash
hashcat -m 1000 -a 0 hash.txt wordlist.txt  # NTLM (%33.33)
hashcat -m 0    -a 0 hash.txt wordlist.txt  # MD5  (%22.22)
```

### 3) Hash Uzunluğu Gösterimi

```bash
[+] Uzunluk:
    32 karakter
```

### 4) Toplu Analizde İstatistik

 - Dosya analizi sonrası en çok bulunan hash türlerini gösterir
 - Başarılı/başarısız analiz sayısı

### 5) Gelişmiş Filtreleme

 - Generic ve Base64 türleri otomatik filtrelenir
 - Daha spesifik eşleşmeler önceliklendirilir

### 6) Hata Yönetimi

 - Regex hatalarını yakalar ve atlar
 - Dosya yolunu gösterir
```bash
# Tek hash test
python hashknock.py -h "5f4dcc3b5aa765d61d8327deb882cf99"

# MySQL hash test (yıldız ile başlayan)
python hashknock.py -h "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"

# Salt'lı hash test
python hashknock.py -h "5f4dcc3b5aa765d61d8327deb882cf99:mysalt123"

# Verbose mod
python hashknock.py -h "hash_değeri" -v
```
