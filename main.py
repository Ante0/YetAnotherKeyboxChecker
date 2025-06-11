import os
import re
import requests
import time
from colorama import Fore, Style, init
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from collections import defaultdict

def get_online_serial_list():
    try:
        response = requests.get("https://android.googleapis.com/attestation/status?" + str(int(time.time())), headers={'Cache-Control': 'no-cache'}, timeout=10)
        response.raise_for_status()
        return set(
            re.sub(r'[^a-f0-9]', '', line.strip().lower())
            for line in response.text.splitlines() 
            if line.strip()
        )
    except Exception as e:
        print(f"Error downloading online Attestation list: {e}")
        exit(1)

def process_certificate(cert_pem, online_serials):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        
        hex_serial = format(cert.serial_number, 'x').lower()
        hex_serial = hex_serial.lstrip('0')
        
        issuer_serial = None
        for attr in cert.issuer:
            if attr.oid == x509.NameOID.SERIAL_NUMBER:
                issuer_serial = re.sub(r'[^a-f0-9]', '', attr.value.lower())
                break
        
        found = hex_serial in online_serials or (issuer_serial and issuer_serial in online_serials)
        
        return hex_serial, issuer_serial, found
    
    except Exception as e:
        print(f"Certificate processing error: {str(e)}")
        return None, None, False

def main():
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    
    found_count = 0
    total_count = 0
    files_with_matches = defaultdict(list)

    print("\nDownloading online Attestation list...")
    online_serials = get_online_serial_list()

    xml_files = [f for f in os.listdir(SCRIPT_DIR) if f.lower().endswith('.xml')]
    
    if not xml_files:
        print("\nNo XML files found in script directory")
        return
    
    for xml_file in xml_files:
        file_matches = 0
        total_count += 1
        print(f"\nProcessing {xml_file}...")
        with open(os.path.join(SCRIPT_DIR, xml_file), 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().split('</CertificateChain>')[0]
        
        certs = re.findall(r'(-----BEGIN CERTIFICATE.*?-----END CERTIFICATE.*?-----)', content, re.DOTALL)
        
        if not certs:
            print("  No certificates found")
            continue
        
        for i, cert in enumerate(certs, 1):
            cert = cert.strip()
            hex_serial, issuer_serial, is_found = process_certificate(cert, online_serials)
            
            print(f"\n  Certificate {i}:")
            print(f"    Hex Serial: {hex_serial or 'N/A'}")
            print(f"    Issuer Serial: {issuer_serial or 'N/A'}")
            
            if is_found:
                print(f"    {Fore.RED}STATUS: REVOKED{Style.RESET_ALL}")
                found_count += 1
                file_matches += 1
                # Store match details
                files_with_matches[xml_file].append({
                    'cert_number': i,
                    'hex_serial': hex_serial,
                    'issuer_serial': issuer_serial
                })
        
        if file_matches:
            print(f"\n  Found {file_matches} matches in {xml_file}")
    
    # Final summary
    print("\n\n=== FINAL RESULTS ===")
    print(f"Total number of keyboxes: {total_count}")
    print(f"Total number of valid keyboxes: {Fore.GREEN}{total_count - found_count}{Style.RESET_ALL}")
    print(f"Total number of revoked keyboxes: {Fore.RED}{found_count}{Style.RESET_ALL}")
    
    if files_with_matches:
        print("\nKeyboxes containing matching serials:")
        for file_name, matches in files_with_matches.items():
            print(f"\n{file_name}:")
            for match in matches:
                print(f"{Fore.RED}STATUS: REVOKED{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        import cryptography
    except ImportError:
        print("Error: cryptography package not installed. Install with:")
        print("pip install cryptography")
        exit(1)
    try:
        import colorama
    except ImportError:
        print("Error: colorama package not installed. Install with:")
        print("pip install colorama")
        exit(1)
    try:
        import requests
    except ImportError:
        print("Error: requests package not installed. Install with:")
        print("pip install requests")
        exit(1)
    main()
