# Laurence Leysen Toolkit

Voor ons afsluitend project van het Python-gedeelte binnen Ethical Hacking moesten we een toolkit maken als basis voor pentesting. Ik heb mijn best gedaan om ervoor te zorgen dat deze toolkit een stevige basis heeft. De manier waarop we de toolkit aanspreken en activiteiten loggen is opgezet met een structuur waardoor het simpel is om nieuwe code toe te voegen.



## Requirements
De te installeren modules kan je ook terugvinden in requirements.txt
Ook heb je `sqlmap` noding dit kan je hier terugvinden: https://sqlmap.org
```
ftplib
logging
rich
subprocess
nmap
scapy
argparse
paramiko
```

## Disclaimer
Penetration testing should only be conducted in a controlled environment to prevent unintended consequences.
These could include damaging the system being tested, exposing sensitive data, or affecting the productivity of users.
In a controlled environment, testers can ensure that only the intended systems are tested and that any potential harm can be immediately mitigated.

## Algemene argumenten

- `-o` of `--option`: Selecteer een optienummer.
- `-t` of `--target`: Specificeer het doel-IP-adres of de URL.

## Nmap - Netwerkscanner (Optie 1)
De `nmap_scanner`-klasse in je code is ontworpen om Nmap-scans uit te voeren op een doel-IP-adres. Nmap is een krachtig open-sourcehulpprogramma voor netwerkverkenning en beveiligingsaudits.

- `-s` of `--scan_type`: Specificeer het type scan voor Nmap (1 voor basis, 2 voor gedetailleerd, 3 voor agressief, 4 voor aangepast).
- `-a` of `--arguments`: Specificeer aangepaste argumenten voor Nmap.

**Voorbeeld:**
```
python main.py -o 1 -t 192.168.1.1 -s 1 -a /-F
```
**Voorbeeld output**
```
                             =================
                    INFO     Nmap - Netwerkscanner                                                                                                                   
                             Scan type: 1
                             Custom arguments: /-F

                    INFO     192.168.1.1                                                                                                                          
                    INFO     Basic Scan resultaat: {'hostnames': [{'name': 'host.docker.internal', 'type': 'PTR'}], 'addresses': {'ipv4': '192.168.1.1'},
                    'vendor': {}, 'status': {'state': 'up', 'reason': 'localhost-response'}}
```

## Webapplicatie Aanvallen (Optie 2)
Deze methode voert een SQL-injectiescan uit met sqlmap. Het sqlmap-commando wordt opgebouwd met de opgegeven URL en enkele extra opties, zoals `--batch` (geen interactieve modus), `--random-agent` (willekeurige gebruikersagent), `--level` (scan diepte) en `--risk` (risico niveau). Het commando wordt uitgevoerd met behulp van `subprocess.Popen`, en de uitvoer wordt geretourneerd.
        
Let op: Dit script roept sqlmap op via de commandoregel. Zorg ervoor dat sqlmap is geïnstalleerd op het systeem waarop dit script wordt uitgevoer

- `-o` of `--option`: Selecteer optienummer 2.
- `-t` of `--target`: Specificeer de URL van het doel. Voor SQL-injecties moet het een geldige URL zijn waarop SQLMap kan worden toegepast

**Voorbeeld:**
```
python main.py -o 2 -t http://example.com
```
**Voorbeeld output**
```
=================
INFO     Aanvallen op Webapplicaties - SQL-injecties en XSS                                                             
Target URL: http://testphp.vulnweb.com/listproducts.php?cat=*
INFO      Starting scan on http://testphp.vulnweb.com/listproducts.php?cat=*
```

##  Brute-Force Aanvallen (Optie 3):
Het "Brute-Force Aanvallen" gedeelte van het scriptis ontworpen om inlogpogingen uit te voeren met behulp van brute-force-aanvallen op FTP- en SSH-protocollen. 
Hier wat meer uitleg:
1.  **BruteForceTester-klasse:**
    
    -   **Wachtwoordlijst laden:**
        
        -   Er is een methode `load_wordlist` in de `BruteForceTester`-klasse geïmplementeerd om een lijst met wachtwoorden vanuit een bestand te laden.
        -   Het script verwacht dat gebruikers hun wachtwoordlijstbestand 'wordlist.txt' noemen en in de './wordlists'-map plaatsen. Als gebruikers een ander bestand of pad willen gebruiken, kunnen ze deze informatie aanpassen in de broncode.
    -   **FTP-brute force-aanval uitvoeren:**
        
        -   Er is een methode `ftp_brute_force` in de `BruteForceTester`-klasse om een brute-force-aanval op een FTP-server uit te voeren.
        -   Deze methode maakt gebruik van het geladen gebruikersnaam (`username`) en de wachtwoordlijst (`password_list`) om FTP-inlogpogingen uit te voeren.
    -   **SSH-brute force-aanval uitvoeren:**
        
        -   Er is een methode `ssh_brute_force` in de `BruteForceTester`-klasse om een brute-force-aanval op een SSH-server uit te voeren.
        -   Deze methode maakt gebruik van het geladen gebruikersnaam (`username`) en de wachtwoordlijst (`password_list`) om SSH-inlogpogingen uit te voeren.
2.  **Wachtwoordlijstlocatie:**
    
    -   Gebruikers worden aangemoedigd om hun wachtwoordlijstbestand 'wordlist.txt' in de './wordlists'-map te plaatsen. Als ze een andere naam of locatie voor het wachtwoordbestand willen gebruiken, kunnen ze de code aanpassen.
3.  **Aanpassingen via Argumenten (Optioneel):**
    
    -   Het script kan worden aangepast om het wachtwoordlijstbestand en andere parameters via command line arguments (`args`) te accepteren. Gebruikers kunnen de argumenten zoals '-p' of '--password_list' in de `argparse`-configuratie toevoegen om de scriptflexibiliteit te vergroten.

-   `-p` of `--protocol`: Specificeer het protocol voor brute-force-aanval (ssh of ftp).
-   `-u` of `--username`: Specificeer de gebruikersnaam voor brute-force-aanval.

**Voorbeeld:**
```
python main.py -o 3 -t 192.168.1.1 -p ssh -u admin
```
**Voorbeeld output**
```
INFO     Brute-Force Aanvallen - Inloggegevens testen voor SSH en FTP                                                                            
Target IP: 192.168.1.1
Protocol: ssh

INFO     ssh                                                                                                                                    
INFO     Error: [Errno None] Unable to connect to port 22 on 192.168.1.1
```

## Network Sniffer (Optie 4):

Dit gedeelte van het script is verantwoordelijk voor netwerkverkeer te onderscheppen en te analyseren. Hier is wat het doet:

1.  **Scapy Sniffer-klasse:**
    
    -   Er is een klasse genaamd `scapy_sniffer` geïmplementeerd om sniffing-functionaliteit met behulp van de Scapy-module mogelijk te maken.
2.  **Aangepaste Packet Crafting (Optioneel):**
    
    -   De klasse biedt methoden om aangepaste TCP-, UDP- en ICMP-pakketten te maken en te verzenden op basis van gebruikersinvoer.
    -   Gebruikers kunnen de bron- en doelpoorten, aangepaste vlaggen, aangepaste payload en andere relevante parameters opgeven om aangepaste pakketten te maken en te versturen.
3.  **Packet Sniffing:**
    
    -   Er is een methode `start_sniffing` geïmplementeerd om netwerkverkeer te onderscheppen.
    -   Deze methode maakt gebruik van `Scapy` om netwerkpakketten te onderscheppen tijdens een opgegeven tijdsduur.
    - Gebruikers kunnen de duur van het snuiven specificeren via het argument `-d` of `--duration` bij het uitvoeren van het script.

4.  **Filtering (Optioneel):**
    
    -   Gebruikers kunnen ook een optioneel filter opgeven om alleen specifiek verkeer te onderscheppen. Dit kan worden gespecificeerd met behulp van het argument `-f` of `--filter` bij het uitvoeren van het script.
5.  **Logging en Analyse:**
    
    -   De onderschepte pakketten worden geanalyseerd en enkele details, zoals de bron- en doel-IP-adressen en de rauwe payload, worden gelogd met behulp van het Rich Logging-framework.

-   `-p` of `--protocol`: Specificeer het protocol voor de geselecteerde optie (1 voor TCP, 2 voor UDP, 3 voor ICMP, 4 voor Sniffer).
-   `-sp` of `--source_port`: Specificeer de bronpoort voor het maken van een aangepast pakket.
-   `-dp` of `--destination_port`: Specificeer de bestemmingspoort voor het maken van een aangepast pakket.
-   `-cf` of `--custom_flags`: Specificeer aangepaste vlaggen voor het maken van een aangepast TCP-pakket.
-   `-cp` of `--custom_payload`: Specificeer aangepaste payload voor het maken van een aangepast pakket.
-   `-d` of `--duration`: Specificeer de duur van het snuiven in seconden.
-   `-f` of `--filter`: Specificeer het filter voor het snuiven (bijv. "ip").

**Voor het versturen van een aangepakt TCP-pakket:**:
```
python main.py -o 4 -t 192.168.1.1 -p 1 -sp 12345 -dp 80 -cf "S" -cp "AangepastePayload"
```
**Voorbeeld output**
```
=================
INFO     Network Sniffer - Onderscheppen en sturen van netwerkverkeer                                                                            
Target IP: 192.168.1.1
.
Sent 1 packets.
###[ Ethernet ]###
  dst       = d0:c6:37:9a:d7:47
  src       = 30:5a:3a:6d:56:38
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 44
     id        = 0
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0xb752
     src       = 192.168.1.1
     dst       = 192.168.1.40
     \options   \
###[ TCP ]###
        sport     = http
        dport     = 12345
        seq       = 3141021875
        ack       = 1
        dataofs   = 6
        reserved  = 0
        flags     = SA
        window    = 5840
        chksum    = 0xe156
        urgptr    = 0
        options   = [('MSS', 1460)]
###[ Padding ]###
           load      = '\\xa9r'
INFO     <Sniffed: TCP:1 UDP:0 ICMP:0 Other:0>
```
**Voor het versturen van een aangepakt UDP-pakket:**
```
python main.py -o 4 -t 192.168.1.1 -p 2 -sp 12345 -dp 8080 -cp "AangepastePayload"
```
**Voorbeeld output**
```
INFO     Network Sniffer - Onderscheppen en sturen van netwerkverkeer                                                                            
Target IP: 192.168.1.40

Sent 1 packets.
[01/03/24 21:18:58] INFO     <Sniffed: TCP:0 UDP:0 ICMP:0 Other:0>
```
**Voor het versturen van een aangepakt ICMP-pakket:**
```
python main.py -o 4 -t 192.168.1.1 -p 3
```
**Voorbeeld output**
```
INFO     Network Sniffer - Onderscheppen en sturen van netwerkverkeer                                                                            
Target IP: 192.168.1.1

Sent 1 packets.
###[ Ethernet ]###
  dst       = d0:c6:37:9a:d7:47
  src       = 30:5a:3a:6d:56:38
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 28
     id        = 24843
     flags     =
     frag      = 0
     ttl       = 64
     proto     = icmp
     chksum    = 0x965c
     src       = 192.168.1.1
     dst       = 192.168.1.40
     \options   \
###[ ICMP ]###
     type      = echo-reply
     code      = 0
     chksum    = 0xffff
     id        = 0x0
     seq       = 0x0
     unused    = ''
###[ Padding ]###
     load      = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\x86vc\\xce'

INFO     <Sniffed: TCP:0 UDP:0 ICMP:1 Other:0>
```
**Voor het starten van de sniffer zonder het versturen van pakketten:**
```
python main.py -o 4 -t 192.168.1.1 -d 10 -f "ip"
```
**Voorbeeld output**
```
INFO     Network Sniffer - Onderscheppen en sturen van netwerkverkeer                                                                            main.py:98
                             Target IP: 192.168.1.40
                             Sniffing duration: 30 seconds

[01/03/24 21:23:48] INFO     Sniffing stopped. Captured 9015 packets.
```
## Logging
Logging maakt gebruik van de ingebouwde Python `logging`-module, samen met de `RichHandler` voor opmaak in de console en een aangepaste `TimedRotatingFileHandler` voor logboekrotatie op basis van de datum.

Laten we eens kijken hoe de logging in de code is toegepast:

1.  **Configureren van Logging in het Algemeen Script:**
    
    In het algemene script wordt de logging geconfigureerd met een basisniveau van `INFO` en twee handlers: `RichHandler` voor de console-uitvoer en `TimedRotatingFileHandler` voor het logboekbestand met rotatie op basis van de datum.

```python
# Configureer logging
console = Console()

# Aangepaste formatter om datum aan logregels toe te voegen
class DateFormatter(logging.Formatter):
    def format(self, record):
        record.date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return super().format(record)

# Aangepaste FileHandler om elke dag een nieuw logboek te maken met de datum in de bestandsnaam
current_date = datetime.now().strftime("%Y-%m-%d")
file_handler = TimedRotatingFileHandler(f"logfile_{current_date}.log", when="midnight", interval=1, backupCount=0)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(DateFormatter("%(asctime)s [%(levelname)s] %(message)s"))

# RichHandler voor console-uitvoer
rich_handler = RichHandler(console=console, markup=True)
rich_handler.setLevel(logging.INFO)

# Voeg de aangepaste FileHandler en RichHandler toe aan de logger
logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, rich_handler],
)

```
**Toepassen van Logging in elke Module:**

In elke module roep je de `getLogger(__name__)`-functie aan om een logger-object voor die module te verkrijgen. Dit logger-object wordt gebruikt om logboekberichten vast te leggen.
```
# In elk modulebestand, bijvoorbeeld in nmap_scanner.py
import logging

# Haal de logger op voor de huidige module
logger = logging.getLogger(__name__)

class nmap_scanner:
    def __init__(self, target_ip):
        # ...

    def basic_scan(self):
        # ...
        logger.info(f"[bold green]Basic Scan resultaat:[/bold green] {result}")
        # ...
```
Door deze configuratie wordt de logboekinformatie zowel naar de console als naar een bestand gelogd. De logbestanden worden elke dag geroteerd met de huidige datum in de bestandsnaam. Hierdoor kun je gemakkelijk de logboekinformatie volgen en archiveren.
