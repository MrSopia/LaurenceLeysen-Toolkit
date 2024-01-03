import nmap
import logging

logger = logging.getLogger(__name__)

class nmap_scanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.nm = nmap.PortScanner()

    def basic_scan(self):
        """
        Voer een basis Nmap-scan uit.
        """
        self.nm.scan(self.target_ip, arguments='-sP')
        return self.nm[self.target_ip]

    def detailed_scan(self):
        """
        Voer een gedetailleerde Nmap-scan uit met versiedetectie en OS-detectie.
        """
        self.nm.scan(self.target_ip, arguments='-sV -O')
        return self.nm[self.target_ip]

    def aggressive_scan(self):
        """
        Voer een agressieve Nmap-scan uit met scriptscanning.
        """
        self.nm.scan(self.target_ip, arguments='-A')
        return self.nm[self.target_ip]

    def custom_scan(self, scan_arguments):
        """
        Voer een aangepaste Nmap-scan uit met door de gebruiker gedefinieerde argumenten.
        """
        try:
            self.nm.scan(self.target_ip, arguments=scan_arguments)
            return self.nm[self.target_ip]
        except KeyError as e:
            logger.info(f"[bold red]Fout bij toegang tot scantresultaten: {e}")
            return f"Geen informatie beschikbaar voor {self.target_ip}"
