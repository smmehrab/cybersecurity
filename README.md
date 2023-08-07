# cybersecurity

#### CLI Tools

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
- [gpg](https://gnupg.org/)
- 

#### Online Tools

- [hashes.com](https://hashes.com/en/decrypt/hash)
- [crackstation.net](https://crackstation.net/)
- 

#### Defensive Security

* [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
* Network
  * [tcpdump](https://www.tcpdump.org/)
  * [wireshark](https://www.wireshark.org/)
  * [snort](https://www.snort.org/)
  * [zeek](https://zeek.org/)
  * [network-miner](https://www.netresec.com/?page=NetworkMiner)
  * [brim](https://www.brimdata.io/)
* 

#### Web Hacking

- https://www.postman.com/
- https://portswigger.net/burp
- https://github.com/assetnote/kiterunner
- https://github.com/xmendez/wfuzz
- https://github.com/owasp-amass/amass
- [OWASP Favicon Databse](https://wiki.owasp.org/index.php/OWASP_favicon_database)
- [ffuf](https://github.com/ffuf/ffuf)
- [dirb](https://www.kali.org/tools/dirb/)
- [gobuster](https://www.kali.org/tools/gobuster/)
- [nikto](https://www.kali.org/tools/nikto/)
- [nessus](https://www.tenable.com/products/nessus?utm_campaign=gs-{11596512479}-{110256808302}-{537515898656}_00026644_fy23&utm_promoter=tenable-hv-brand-00026644&utm_source=google&utm_term=nessus&utm_medium=cpc&utm_geo=apac&gclid=CjwKCAjw5remBhBiEiwAxL2M94jwwfvyR4FWvmcRZhAz1xxjoaZSZlPskF3mbHCn9c7zI-DdcrOLbBoCn0IQAvD_BwE)

#### Network Services

* [nmap](https://nmap.org/)
* [enum4linux](https://www.kali.org/tools/enum4linux/)
* [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
* 

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
- File Related
  - [pdfinfo](https://linux.die.net/man/1/pdfinfo)
  - [exiftool](https://exiftool.org/)
- [recon-ng](https://www.kali.org/tools/recon-ng/)
- [maltego](https://www.kali.org/tools/maltego/)
- 

#### Vulnerability Research

- [https://www.exploit-db.com/](https://www.exploit-db.com/)
- [https://www.exploit-db.com/searchsploit](https://www.exploit-db.com/searchsploit)
- [https://nvd.nist.gov/vuln/search](https://nvd.nist.gov/vuln/search)
- [https://cve.mitre.org/](https://cve.mitre.org/)
- [https://www.cvedetails.com/](https://www.cvedetails.com/)

#### Malware Research

- https://github.com/PatrikH0lop/malware_showcase
- 

#### Hardware Tools

- USB Rubber Ducky Using Rasberry Pi Pico
  https://github.com/dbisu/pico-ducky
- FemtoCell
- Stingray

#### Word Lists

- [RockYou](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [jwt-secrets](https://github.com/wallarm/jwt-secrets)
