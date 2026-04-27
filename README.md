# Ion Security

App desktop Electron per Windows orientata a protezione locale e visibilita reale dello stato di sicurezza.

## Cosa fa davvero

- Legge lo stato di Microsoft Defender tramite `Get-MpComputerStatus`
- Verifica i profili del firewall Windows tramite `Get-NetFirewallProfile`
- Controlla lo stato di SmartScreen
- Monitora connessioni attive con `netstat`
- Avvia e ferma tunnel WireGuard usando configurazioni `.conf`
- Usa l'AI solo come assistente opzionale per spiegare i dati raccolti

## Cosa non fa da sola

- Non sostituisce un antivirus completo: usa quello installato nel sistema
- Non crea una VPN proprietaria: gestisce WireGuard gia installato
- Non blocca automaticamente tutte le minacce
- Non garantisce protezione assoluta del PC

## Requisiti

- Windows 10 o Windows 11
- Node.js 18+
- Permessi amministrativi per le funzioni VPN
- WireGuard installato, se vuoi usare la VPN

## Sviluppo

```bash
npm install
npm start
```

## Build installer

```bash
npm run build
```

L'installer Windows NSIS viene generato nella cartella `dist/`.

## Setup VPN reale

1. Installa WireGuard da [wireguard.com](https://www.wireguard.com/install/)
2. Ottieni un file `.conf` dal tuo provider VPN
3. Salva il file in `%USERPROFILE%\domderok-vpn\`
4. Apri l'app come amministratore
5. Seleziona il server e premi `Connetti VPN`

## Nota importante

Per pubblicare seriamente una security app servono anche firma del codice, policy privacy, note legali e test su macchine Windows reali. Questa base ora e piu credibile dal punto di vista funzionale, ma non va presentata come suite di protezione totale senza ulteriore hardening e QA.
