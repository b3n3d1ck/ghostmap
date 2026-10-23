# ghostmap

Pemetaan attack-surface sebuah situs **tanpa wordlist**. Ketik satu URL, ghostmap menemukan direktori, endpoint, dan file tersembunyi bukan dengan menebak ribuan nama, tapi dengan membaca petunjuk yang situs itu bocorkan sendiri: JavaScript, `robots.txt`, `sitemap.xml`, link halaman, dan `.well-known`, lalu menelusurinya secara rekursif.

Satu binary, tanpa dependency. Jalan di **Linux, WSL, Windows (cmd/PowerShell), dan macOS**.

![Go](https://img.shields.io/badge/go-1.24-00ADD8?style=flat-square&logo=go&logoColor=white)
![platform](https://img.shields.io/badge/linux%20·%20wsl%20·%20windows%20·%20macos-222?style=flat-square)
![recon](https://img.shields.io/badge/mode-non--destruktif%20(GET)-4d7c0f?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-333?style=flat-square)

> **Hanya untuk sistem yang kamu miliki atau yang kamu diberi izin tertulis untuk menguji.** Memindai sistem orang lain tanpa izin bisa melanggar hukum (di Indonesia: UU ITE). ghostmap hanya mengirim request GET biasa dan memperkenalkan dirinya lewat User-Agent, tapi tanggung jawab penggunaan ada di tangan kamu.

## Kenapa "tanpa wordlist"

Dir scanner biasa (gobuster, dirb) menembak ribuan tebakan: `/admin`, `/backup`, `/old`, dan seterusnya. Berisik, lambat, dan cuma menemukan nama yang ada di wordlist.

ghostmap ambil jalan lain. Aplikasi web **membocorkan rutenya sendiri** di tempat-tempat ini:

- **JavaScript** — bundel frontend penuh dengan `fetch("/api/v1/users")`, path admin, dan endpoint internal. ghostmap mengekstraknya.
- **robots.txt** — justru sering memuat `/admin/`, `/backup/` yang ingin disembunyikan.
- **sitemap.xml** dan **link di halaman** — rute nyata yang dipakai aplikasi.

Dari situ ghostmap menyusun daftar path nyata, memeriksanya, lalu menelusuri halaman yang ketemu untuk menemukan lebih banyak. Hasilnya jauh lebih relevan daripada brute force, dan jauh lebih sunyi.

## Yang ditemukan

- **Path & endpoint** hasil ekstraksi (dengan status, ukuran, judul, dan dari mana ditemukan)
- **File sensitif terekspos**: `.env`, `.git/config`, backup, `phpinfo.php`, `docker-compose.yml`, dan lainnya — dengan bukti, dan nilai yang terlihat seperti password/kunci otomatis **disensor**
- **Fingerprint teknologi**: dari header, cookie, dan body (Laravel, Next.js, WordPress, dll)
- **Header keamanan yang hilang**: CSP, HSTS, X-Frame-Options, dan lainnya

## Contoh

```console
$ ghostmap https://target-punyamu.com

RINGKASAN  42 request · 2449ms

TEKNOLOGI
  › Laravel
  › Server: nginx/1.18.0
  › X-Powered-By: PHP/8.1.2

HEADER KEAMANAN HILANG
  Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, ...

⚠ FILE TEREKSPOS
  ✱ /.env                  File .env berisi kredensial
      APP_KEY=*** DB_PASSWORD=*** MAIL_PASSWORD=***
  ✱ /.git/config           Folder .git terekspos, kode sumber bisa diunduh

PATH DITEMUKAN (6)
  200  /admin/                   [robots]  57B · Admin
  200  /api/v1/admin/config      [js]      14B
  200  /api/v1/users             [js]      10B
  200  /dashboard                [html]    57B · Dashboard
  200  /login                    [html]    56B · Login
  200  /static/app.js            [html]    114B
```

`[js]` artinya endpoint itu ditemukan di dalam file JavaScript, bukan ditebak.

## Instalasi

**Opsi 1 — unduh binary** (tanpa install apa pun): ambil dari halaman [Releases](https://github.com/bramcps/ghostmap/releases), ekstrak, jalankan.

**Opsi 2 — pakai Go** (butuh Go 1.24+):

```bash
go install github.com/bramcps/ghostmap@latest
```

**Opsi 3 — build dari sumber:**

```bash
git clone https://github.com/bramcps/ghostmap.git
cd ghostmap
go build -o ghostmap .
```

Di Windows tinggal jalankan `ghostmap.exe` dari cmd atau PowerShell. Di WSL/Ubuntu, `./ghostmap`.

## Pemakaian

```bash
ghostmap https://target-punyamu.com
ghostmap -c 40 -depth 3 https://target-punyamu.com      # lebih cepat, lebih dalam
ghostmap -rate 10 https://target-punyamu.com            # batasi 10 req/detik (sopan)
ghostmap -json -o hasil.json https://target-punyamu.com # simpan laporan JSON
```

| Opsi | Arti |
|---|---|
| `-c` | jumlah request paralel (default 20) |
| `-depth` | berapa putaran rekursi untuk halaman yang di-crawl (default 2) |
| `-rate` | batas request/detik, 0 = tanpa batas |
| `-max` | batas keras total request (default 2000) |
| `-timeout` | timeout per request |
| `-json` / `-o` | keluaran JSON ke layar / ke file |
| `-insecure` | lewati verifikasi sertifikat TLS |
| `-ua` | ganti User-Agent |

## Cara kerja

1. Ambil halaman utama, baca `robots.txt`, `sitemap.xml`.
2. Unduh file JavaScript yang dimuat halaman, ekstrak path/endpoint dengan regex (gaya LinkFinder).
3. Susun kandidat path + prefix direktorinya, lalu periksa semuanya secara paralel.
4. Dari halaman HTML yang ketemu, ekstrak link baru dan ulangi sampai kedalaman tertentu.
5. Periksa daftar file sensitif dengan baseline anti soft-404 (hanya ditandai kalau isinya cocok tanda tangan).
6. Susun laporan: path, file terekspos, teknologi, header.

Semua request adalah **GET** biasa. Tidak ada payload serangan, tidak ada eksploitasi, tidak ada yang ditulis ke target.

## Batasan

- Menemukan yang **direferensikan**. Endpoint yang tidak disebut di mana pun (benar-benar tersembunyi) tidak akan muncul — itu memang disengaja, karena menemukannya butuh brute force yang berisik.
- Fingerprint berbasis pola, bisa meleset pada setup yang tidak biasa.

## Kontribusi

Tambahan pola ekstraksi, tanda tangan file sensitif, atau fingerprint teknologi sangat diterima. Tambahkan + tesnya (`go test ./...`), lalu kirim pull request. Jangan menambah apa pun yang menyerang atau mengeksploitasi target — ghostmap sengaja dijaga sebagai alat recon non-destruktif.

## Lisensi

[MIT](LICENSE) © 2025 Mas Bram. Untuk riset keamanan yang sah dan pengujian yang diizinkan. Kalau berguna, kasih ⭐.
