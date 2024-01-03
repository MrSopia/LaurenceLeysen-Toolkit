from rich.console import Console
from rich.panel import Panel
from rich.logging import RichHandler

from datetime import datetime

import argparse

import logging
from logging.handlers import TimedRotatingFileHandler

from modules.nmap_scanner import nmap_scanner
from modules.sqli_scanner import sqli_scanner
from modules.brute_force import BruteForceTester
from modules.scapy_sniffer import scapy_sniffer

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

# Configure logger
logger = logging.getLogger(__name__)

#configure argparse
def parse_arguments():
    parser = argparse.ArgumentParser(description="Penetration/framework toolkit options")
    parser.add_argument("-o", "--option", type=int, help="Select an option number")
    parser.add_argument("-t", "--target", type=str, help="Specify the target IP address or URL")
    parser.add_argument("-s", "--scan_type", type=int, help="Specify the type of scan (for Nmap)")
    parser.add_argument("-a", "--arguments", type=str, help="Specify custom arguments (for Nmap)")
    parser.add_argument("-d", "--duration", type=int, help="Specify the duration for sniffing (for Scapy sniffer)")
    parser.add_argument("-f", "--filter", type=str, help="Specify the filter for sniffing (for Scapy sniffer)")
    parser.add_argument("-p", "--protocol", type=str, help="Specify the protocol for selected option (S/A/F/SA/PA/ssh/ftp)")
    parser.add_argument("-sp", "--source_port", type=int, help="Specify the source port for crafting a custom packet (for Scapy sniffer)")
    parser.add_argument("-dp", "--destination_port", type=int, help="Specify the destination port for crafting a custom packet (for Scapy sniffer)")
    parser.add_argument("-cf", "--custom_flags", type=str, help="Specify custom flags for crafting a custom TCP packet (for Scapy sniffer)")
    parser.add_argument("-cp", "--custom_payload", type=str, help="Specify custom payload for crafting a custom packet (for Scapy sniffer)")
    parser.add_argument("-u", "--username", type=str, help="Specify username for bruteforcing")

    return parser.parse_args()

def log_user_choice(text):
    user_choice = input(text)
    logger.info(f"User selecteerd: {user_choice}")
    return user_choice

def display_intro():
    intro_text = """
    [bold magenta]Penetration/framework toolkit[/bold magenta]
    """
    logger.info(intro_text)

def display_section(section_title, section_content):
    logger.info(f"== {section_title} ==\n{section_content}\n{'=' * (len(section_title) + 6)}")

def display_analysis():
    analysis_text = """
    [bold red]Penetration testing should only be conducted in a controlled environment to prevent unintended consequences.[/bold red]
    [bold red]These could include damaging the system being tested, exposing sensitive data, or affecting the productivity of users.[/bold red]
    [bold red]In a controlled environment, testers can ensure that only the intended systems are tested and that any potential harm can be immediately mitigated.[/bold red]
    """
    display_section("Information", analysis_text)

def display_option(args):
    option_text = ""
    if args.option and args.option == 1:
        option_text += "Nmap - Netwerkscanner\n"
        if args.scan_type:
            option_text += f"Scan type: {args.scan_type}\n"
        if args.arguments:
            option_text += f"Custom arguments: {args.arguments}\n"
    elif args.option and args.option == 2:
        option_text += "Aanvallen op Webapplicaties - SQL-injecties en XSS\n"
        if args.target:
            option_text += f"Target URL: {args.target}\n"
    elif args.option and args.option == 3:
        option_text += "Brute-Force Aanvallen - Inloggegevens testen voor SSH en FTP\n"
        if args.target:
            option_text += f"Target IP: {args.target}\n"
        if args.protocol:
            option_text += f"Protocol: {args.protocol}\n"
    elif args.option and args.option == 4:
        option_text += "Network Sniffer - Onderscheppen en sturen van netwerkverkeer\n"
        if args.target:
            option_text += f"Target IP: {args.target}\n"
        if args.duration:
            option_text += f"Sniffing duration: {args.duration} seconds\n"
        if args.filter:
            option_text += f"Sniffing filter: {args.filter}\n"
    else:
        option_text += "Invalid option number\n"

    logger.info(option_text)

# Hoofdcode voor het weergeven van de UI
if __name__ == "__main__":
    args = parse_arguments()

    display_intro()
    display_analysis()

    display_option(args)

    # Handle user choice
    if args.option == 1:
        logging.info(args.target)
        scan = nmap_scanner(args.target)
        # Handle Nmap logic
        if args.scan_type:
            type_scan_choice = str(args.scan_type)
        else:
            type_scan_choice = input("Selecteer een optie (geef het correcte nummer): ")

        match type_scan_choice:
            case "1":
                result = scan.basic_scan()
                logger.info(f"[bold green]Basic Scan resultaat:[/bold green] {result}")
            case "2":
                result = scan.detailed_scan()
                logger.info(f"[bold green]Gedetailleerde Scan resultaat:[/bold green] {result}")
            case "3":
                result = scan.aggressive_scan()
                logger.info(f"[bold green]Aggressieve Scan resultaat:[/bold green] {result}")
            case "4":
                logger.info(args.arguments)
                if args.arguments:
                    arguments = args.arguments
                else:
                    arguments = input("Geef de argumenten: ")
                result = scan.custom_scan(arguments)
                logger.info(f"[bold green]Aangepaste Scan resultaat:[/bold green] {result}")
            case _:
                logger.info(f"[bold red]Verkeerde input.[/bold red]")
    elif args.option == 2:
        # Handle SQLi and XSS logic
        logger.info(f"[bold green] Starting scan on {args.target}")
        scanner = sqli_scanner(args.target)
        output = scanner.run_scan()
        logger.info(output)
    elif args.option == 3:
        # Handle Brute Force logic
        password_list = BruteForceTester.load_wordlist()
        brute_force_tester = BruteForceTester(args.target)
        logger.info(args.protocol)
        match args.protocol.lower():
            case "ftp":
                ftp_result = brute_force_tester.ftp_brute_force(args.username, password_list)
                logger.info(f"[bold green]FTP resultaat:[/bold green] {ftp_result}")
            case "ssh":
                ssh_result = brute_force_tester.ssh_brute_force(args.username, password_list)
                logger.info(f"[bold green]SSH resultaat:[/bold green] {ssh_result}")
            case _:
                logger.info(f"[bold red]Verkeerde input.[/bold red]")
    elif args.option == 4:
        type_scan_choice = str(args.protocol)
        sniffer = scapy_sniffer(args.target)
        match type_scan_choice:
            case "1":
                source_port = args.source_port
                destination_port = args.destination_port
                custom_flags = args.custom_flags
                custom_payload = args.custom_payload
                sniffer.craft_and_send_tcp_packet(source_port, destination_port, custom_flags, custom_payload)

            case "2":
                source_port = args.source_port
                destination_port = args.destination_port
                custom_payload = args.custom_payload
                sniffer.craft_and_send_udp_packet(source_port, destination_port, custom_payload)

            case "3":
                sniffer.craft_and_send_icmp_packet()
            
            case "4":
                duration = args.duration
                result = sniffer.start_sniffing(duration=int(duration), filter="ip")
                logger.info(f"{result}")

            case _:
                logger.info(f"[bold red]Verkeerde input.[/bold red]")

    else:
        print("Verkeerde input.")