# log_analyzer.py

def analyser_logg(filnavn, maks_feil=3):
    print(f"--- Starter analyse av {filnavn} ---")
    
    # En ordbok (dictionary) for å telle feil per IP-adresse
    feil_teller = {}

    try:
        # Åpne og les loggfilen linje for linje
        with open(filnavn, 'r') as fil:
            for linje in fil:
                # Vi sjekker om linjen inneholder teksten for feilet innlogging
                if "Invalid password" in linje:
                    # Enkel tekstsplitting for å hente ut IP-adressen (siste ordet i linjen)
                    ord_i_linje = linje.split()
                    ip_adresse = ord_i_linje[-1]
                    
                    # Øk telleren for denne IP-adressen
                    if ip_adresse in feil_teller:
                        feil_teller[ip_adresse] += 1
                    else:
                        feil_teller[ip_adresse] = 1

        # Sjekk om noen har gått over grensen for antall tillatte feil
        mistenkelig_aktivitet_funnet = False
        print("\n[ALERT] Følgende IP-adresser flagges for mistenkelig aktivitet:")
        
        for ip, antall in feil_teller.items():
            if antall >= maks_feil:
                print(f"⚠️ IP: {ip} har {antall} mislykkede innloggingsforsøk!")
                mistenkelig_aktivitet_funnet = True
                
        if not mistenkelig_aktivitet_funnet:
            print("✅ Ingen mistenkelig aktivitet funnet i loggen.")

    except FileNotFoundError:
        print(f"Feil: Fant ikke filen '{filnavn}'. Sjekk at den ligger i samme mappe.")

# Kjør funksjonen på testloggen vår
if __name__ == "__main__":
    analyser_logg("server_log.txt", maks_feil=3)
