# log_analyzer.py

def analyser_logg(filnavn, maks_feil=3, blacklist_fil="blacklist.txt"):
    print(f"--- Starter avansert analyse av {filnavn} ---")
    
    feil_teller = {}

    try:
        # 1. Les og analyser loggfilen
        with open(filnavn, 'r') as fil:
            for linje in fil:
                if "Invalid password" in linje:
                    ord_i_linje = linje.split()
                    ip_adresse = ord_i_linje[-1]
                    
                    if ip_adresse in feil_teller:
                        feil_teller[ip_adresse] += 1
                    else:
                        feil_teller[ip_adresse] = 1

        # 2. Sjekk etter mistenkelig aktivitet og oppdater blacklist
        mistenkelig_aktivitet_funnet = False
        mistenkelige_ips = []

        for ip, antall in feil_teller.items():
            if antall >= maks_feil:
                mistenkelige_ips.append(ip)
                mistenkelig_aktivitet_funnet = True

        if mistenkelig_aktivitet_funnet:
            print(f"\n[ALERT] Fant {len(mistenkelige_ips)} IP-adresse(r) som overskred grensen.")
            
            # Skriv de flaggede IP-adressene til blacklist.txt
            with open(blacklist_fil, 'w') as b_fil:
                for ip in mistenkelige_ips:
                    print(f"⚠️ Flagget: {ip} (Forsøk: {feil_teller[ip]}) -> Lagres i {blacklist_fil}")
                    b_fil.write(f"{ip}\n")
            print(f"✅ {blacklist_fil} ble vellykket oppdatert.")
        else:
            print("✅ Ingen mistenkelig aktivitet funnet i loggen.")

    except FileNotFoundError:
        print(f"Feil: Fant ikke filen '{filnavn}'. Sjekk at den ligger i samme mappe.")

if __name__ == "__main__":
    analyser_logg("server_log.txt", maks_feil=3)
