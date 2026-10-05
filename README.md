# WSB Passkey 🔑

> Sprzętowy „klucz USB” do automatycznego logowania na portalach uczelni (MeritoGo / WSB Merito) z automatycznym wylogowaniem i czyszczeniem śladów po wyjęciu nośnika.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)]()
[![Release](https://img.shields.io/badge/Download-WSBPasskey.exe-success.svg)](https://github.com/JAMAKOCZI/wsb-passkey/releases)

---

## ⚡ Szybki start (Bez instalowania czegokolwiek)

**Nie musisz instalować Pythona ani niczego kompilować.** 

### 1. Pobierz program
Wejdź w zakładkę **[Releases](https://github.com/JAMAKOCZI/wsb-passkey/releases)** po prawej stronie i pobierz gotowy plik **`WSBPasskey.exe`**.

### 2. Wrzuć na pendrive
Skopiuj pobrany plik `WSBPasskey.exe` bezpośrednio na swój pendrive.
> **Czy plik musi być w folderze?**  
> **Nie!** Może leżeć luzem w katalogu głównym pendrive'a (np. `E:\WSBPasskey.exe`), tak aby był pod ręką zaraz po podłączeniu. Program automatycznie utworzy obok siebie zaszyfrowany plik z danymi (`wsb_passkey.dat`).

### 3. Skonfiguruj na swoim komputerze (robisz to tylko raz)
1. Uruchom `WSBPasskey.exe` z pendrive'a na swoim prywatnym komputerze.
2. Wyskoczy okno pierwszej konfiguracji:
   - Podaj swój uczelniany adres e-mail (np. `12345@student.merito.pl`),
   - Wpisz hasło do konta uczelnianego,
   - Wymyśl swój **PIN** (minimum 6 znaków).
3. Gotowe! Twoje hasło zostało zaszyfrowane w pliku `wsb_passkey.dat` na pendrivie.

### 4. Użycie na uczelni
1. Wkładasz pendrive do portu USB w sali komputerowej.
2. Uruchamiasz `WSBPasskey.exe` i wpisujesz swój PIN.
3. Przeglądarka otwiera się, sama przechodzi przez bramkę logowania WSB oraz Microsoft i loguje Cię na konto MeritoGo.
4. **Kończysz pracę? Po prostu wyjmij pendrive.**
   - W ciągu 1-2 sekund program wyloguje sesję z serwerów uczelni i Microsoftu, zamknie przeglądarkę i bezpowrotnie skasuje cały tymczasowy profil (ciasteczka, historię, hasła). Na komputerze uczelni nie zostaje żaden ślad.

---

## O co chodzi? (Problem)

Logowanie na komputerach w pracowniach uczelnianych to mały koszmar:
- Uczelniany login to zazwyczaj długi ciąg znaków (np. `12345@student.merito.pl`).
- Wpisywanie złożonego hasła na oczach całej sali wykładowej/ćwiczeniowej nie należy do bezpiecznych ani wygodnych.
- Najgorsze: **zapomnienie o wylogowaniu się**. Zostawienie aktywnej sesji Microsoft 365 / MeritoGo na komputerze w sali oznacza, że kolejna osoba ma pełen dostęp do Twoich ocen, dokumentów, czatów Teams i poczty.

**WSB Passkey** zamienia zwykły pendrive w fizyczny token bezpieczeństwa – jak klucz U2F/FIDO, ale dopasowany do specyfiki uczelnianych portali logowania.

---

## Architektura i rozwiązane problemy

Napisanie prostego skryptu w Selenium zajmuje 10 minut, ale **nie zadziała on w realnych warunkach pracowni komputerowej**. Uczelniane pecety mają specyficzne ograniczenia, które ten projekt rozwiązuje od podstaw:

### 1. Zero uprawnień administratora (Standard User)
Na uczelni nikt nie da Ci konta admina.
- Nie używamy żadnych sterowników, usług systemowych ani wpisów w rejestrze.
- Nie instalujemy Selenium ani zewnętrznych binarek chromedriver/msedgedriver (które wymagają zgodności wersji).
- Sterowanie opiera się na natywnym **Chrome DevTools Protocol (CDP)** przez lokalny websocket na `127.0.0.1`, bezpośrednio z wbudowanym w każdy Windows 10/11 Microsoft Edge (lub Google Chrome).

### 2. Problem wyjmowania pendrive'a (`STATUS_IN_PAGE_ERROR`)
W systemie Windows odłączenie nośnika, z którego bezpośrednio pracuje proces PE, potrafi wywołać błąd stronicowania pamięci (`0xC0000006`) i natychmiastowy crash programu zanim ten zdąży cokolwiek zamknąć.
- **Rozwiązanie:** Program po uruchomieniu z pendrive'a kopiuje proces do `%TEMP%` i stamtąd nadzoruje sesję.
- **Odporność na AppLocker:** Jeśli polityka bezpieczeństwa uczelni blokuje odpalanie `.exe` z katalogu Temp, program automatycznie to wykrywa i przełącza się na bezpieczne działanie in-place wprost z pendrive'a.

### 3. Pewna identyfikacja pendrive'a (Volume Serial Number)
Samo sprawdzanie czy litera dysku (np. `E:\`) istnieje to za mało – ktoś mógłby wyjąć Twój pendrive i włożyć inny.
- **Rozwiązanie:** Program przy starcie pobiera unikalny numer seryjny woluminu USB przez WinAPI (`GetVolumeInformationW`). Jeśli w porcie pojawi się inny pendrive o tej samej literze, program natychmiast to wykryje i zamknie sesję.

### 4. Wiszące procesy potomne Edge i blokady plików
Chromium po zamknięciu okna często zostawia w tle procesy pomocnicze (GPU, renderery, crashpad). Zablokowane przez nie pliki w `%TEMP%` uniemożliwiają skasowanie ciasteczek sesyjnych (`Access Denied`).
- **Rozwiązanie:** Przeglądarka jest przypinana do jądrowego obiektu zadań Windows (**Job Object**) z flagą `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Przy wyjściu system Windows sprzętowo ubija całe drzewo procesów w 0 ms, dzięki czemu profil tymczasowy jest usuwany w 100% natychmiastowo.

### 5. Uczelniane serwery Proxy
W sieciach akademickich często stosowane jest proxy HTTP. Standardowe biblioteki potrafią próbować łączyć się z portem debugera (`127.0.0.1`) przez zewnętrzne proxy uczelni, co kończy się błędem `502 Bad Gateway`.
- **Rozwiązanie:** Wymuszenie `NO_PROXY` oraz jawny `ProxyHandler({})` dla całej komunikacji loopback.

### 6. Detekcja botów (Cloudflare / Microsoft Entra ID)
Standardowe włączenie portu debugowania ustawia w przeglądarce `navigator.webdriver = true`, co wyzwala mechanizmy anty-botowe Microsoftu i CAPTCHA.
- **Rozwiązanie:** Flaga `--disable-blink-features=AutomationControlled` wymusza `navigator.webdriver = false`. Dla serwerów logowania sesja wygląda jak zwykła, ręcznie otwarta przeglądarka.

---

## Bezpieczeństwo kryptograficzne

- **AES-256-GCM:** Dane logowania są szyfrowane symetrycznie algorytmem ze sprawdzaniem integralności (AEAD).
- **KDF scrypt ($N=131072, r=8, p=1$):** Klucz szyfrujący wyprowadzany jest z Twojego PIN-u przy użyciu pamięciożernej funkcji scrypt. Każda próba sprawdzenia PIN-u wymaga zaalokowania **128 MB RAM**, co uniemożliwia masowy atak brute-force na kartach graficznych w razie zgubienia pendrive'a.
- **Czyszczenie RAM:** Hasło w postaci jawnej jest usuwane i nadpisywane w pamięci procesu natychmiast po wysłaniu formularza logowania (`_wipe_creds`).
- **Anti-Brute Force:** Po 3 błędnych próbach wprowadzenia PIN-u program bezpowrotnie przerywa działanie.
- **Ochrona konta przed blokadą:** W przypadku zmiany hasła program przerywa po jednej próbie – nie uderza w pętli w serwer uczelni, co chroni konto przed zablokowaniem w Active Directory.

---

## 🛠️ Dla programistów: Budowanie ze źródeł (opcjonalne)

Jeśli wolisz sam zbudować plik `.exe` z kodu źródłowego:

```bash
# 1. Sklonuj repozytorium
git clone https://github.com/JAMAKOCZI/wsb-passkey.git
cd wsb-passkey

# 2. Uruchom skrypt budujący (wymaga Python 3.10+)
build.bat
```

W katalogu `dist\` powstanie plik `WSBPasskey.exe`.

---

## Struktura repozytorium

```
wsb-passkey/
├── wsb_passkey.py      # Główny kod źródłowy aplikacji (Python/Tkinter/CDP/WinAPI)
├── build.bat           # Skrypt kompilacji do pojedynczego .exe (PyInstaller)
├── requirements.txt    # Zależności biblioteczne (cryptography, websocket-client, pyinstaller)
├── .gitignore          # Ignorowanie plików tymczasowych, buildów i kluczy *.dat
├── LICENSE             # Licencja MIT
└── README.md           # Niniejsza dokumentacja
```

---

## Opcje zaawansowane (CLI)

Program można uruchamiać również z wiersza poleceń:

```bash
# Wymuszenie ponownej konfiguracji danych logowania
WSBPasskey.exe --setup

# Wymuszenie konkretnej przeglądarki (domyślnie Edge, fallback Chrome)
WSBPasskey.exe --browser chrome

# Wskazanie innego folderu z kluczem wsb_passkey.dat
WSBPasskey.exe --usb-dir E:\
```

---

## Ograniczenia i uwagi

- **Firefox:** Ze względu na brak wsparcia dla protokołu CDP w nowszych wersjach Firefoksa, wspierane są przeglądarki oparte o silnik Chromium (Microsoft Edge, Google Chrome). Na każdym komputerze z Windows dostępny jest wbudowany Edge.
- **Logowanie wieloskładnikowe (MFA):** Jeśli na Twoim koncie uczelnia włączy weryfikację dwuetapową (np. powiadomienie na telefonie w aplikacji Microsoft Authenticator), program poprawnie przejdzie krok loginu i hasła, a następnie zaczeka do 90 sekund, aż zatwierdzisz powiadomienie na swoim telefonie.
- **Zgubienie pendrive'a:** Mimo silnego szyfrowania (AES-256 + scrypt), dobrą praktyką bezpieczeństwa w przypadku fizycznej utraty nośnika jest prewencyjna zmiana hasła do konta w portalu uczelni.

---

## Licencja

Projekt udostępniany na licencji [MIT](LICENSE). Możesz go dowolnie modyfikować i dostosowywać do innych portali studenckich.
