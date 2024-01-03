from scapy.all import IP, TCP, UDP, ICMP, sniff, send
import logging

# Haal de logger op die geconfigureerd is in het hoofdscript
logger = logging.getLogger(__name__)

class scapy_sniffer:
    def __init__(self, target_ip):
        self.packet_count = 0
        self.target_ip = target_ip

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload = packet[IP].payload

            # Controleer op wachtwoorden in de payload
            if "password" in str(payload).lower():
                logger.info(f"Mogelijk wachtwoord vastgelegd van {src_ip} naar {dst_ip}")
                logger.info("Raw Payload:")
                logger.info(payload)
                logger.info("=" * 40)

            self.packet_count += 1

    def start_sniffing(self, duration=10, filter="ip"):
        try:
            sniff(prn=self.packet_callback, filter=filter, store=0, timeout=duration)
            return(f"[bold green]Sniffing gestopt. {self.packet_count} pakketten vastgelegd.[/bold green]")
        except KeyboardInterrupt:
            pass
        return("[bold red]Sniffing mislukt[/bold red]")

    def send_and_sniff(self, packet, filter_condition=None, timeout=2):
        # Stuur het pakket en vang de reacties op
        send(packet)
        if filter_condition:
            responses = sniff(filter=filter_condition, count=1, timeout=timeout)
        else:
            responses = sniff(count=1, timeout=timeout)

        # Toon de vastgelegde reacties
        for response in responses:
            response.show()

        logger.info(responses)

    def craft_and_send_tcp_packet(self, source_port, dest_port, flags, payload=None):
        source_port = int(source_port)
        dest_port = int(dest_port)
        # Maak een aangepast TCP-pakket
        packet = IP(dst=self.target_ip) / TCP(sport=source_port, dport=dest_port, flags=flags)

        # Voeg payload toe (indien opgegeven)
        if payload:
            packet = packet / payload

        # Verstuur en leg het TCP-pakket vast
        self.send_and_sniff(packet, filter_condition=f"src {self.target_ip} and dst port {source_port}")

    def craft_and_send_udp_packet(self, source_port, dest_port, payload=None):
        # Zorg ervoor dat source_port en dest_port integers zijn
        source_port = int(source_port)
        dest_port = int(dest_port)

        # Maak een aangepast UDP-pakket
        packet = IP(dst=self.target_ip) / UDP(sport=source_port, dport=dest_port)

        # Voeg payload toe (indien opgegeven)
        if payload:
            packet = packet / payload

        # Verstuur en leg het UDP-pakket vast
        self.send_and_sniff(packet, filter_condition=f"src {self.target_ip} and dst port {dest_port}")

    def craft_and_send_icmp_packet(self):
        # Maak een ICMP-pakket (ping)
        packet = IP(dst=self.target_ip) / ICMP()

        # Verstuur en leg het ICMP-pakket vast
        self.send_and_sniff(packet, filter_condition=f"src {self.target_ip}")
