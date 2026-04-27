# Ion Security

Ion Security e un'app desktop Windows orientata a protezione locale, monitoraggio reale della rete e reazione automatica a connessioni sospette.

## Funzioni principali

- Controlla lo stato reale di Microsoft Defender tramite `Get-MpComputerStatus`
- Verifica i profili del firewall Windows tramite `Get-NetFirewallProfile`
- Controlla SmartScreen
- Monitora connessioni attive reali con `netstat`
- Classifica connessioni remote per rischio usando IP, porte e geolocalizzazione
- Mostra l'IP remoto sospetto all'utente
- Prova a bloccare automaticamente IP sospetti tramite `Windows Firewall`
- Registra gli IP gia bloccati per evitare duplicati
- Gestisce tunnel WireGuard tramite file `.conf`
- Include un assistente locale integrato che legge i dati reali raccolti dall'app

## Protezione attiva

Quando la protezione attiva e abilitata, Ion Security:

- segnala all'utente gli IP remoti classificati ad alto rischio
- prova a espellerli bloccando il traffico verso quell'IP con una regola firewall
- associa quando possibile IP, porta, PID e nome processo

## Bootstrap automatico

Al primo avvio l'app puo:

- creare le cartelle necessarie
- installare WireGuard con `winget`
- attivare il firewall Windows
- aggiornare le firme di Defender
- impostare SmartScreen su modalita `Warn`

## Limiti realistici

- Non puo promettere il blocco del 100% di tutte le minacce
- Non sostituisce completamente un antivirus engine proprietario
- Per una VPN reale serve comunque almeno un file `.conf` del provider nella cartella VPN
- Il blocco automatico dipende dai dati che Windows espone davvero al momento del rilevamento

## Requisiti

- Windows 10 o Windows 11
- Permessi amministrativi per funzioni firewall, Defender e VPN
- Node.js 18+ per sviluppo locale

## Sviluppo

```bash
npm install
npm start
```

## Build

```bash
npm run pack
```

La build pronta all'uso viene generata in `dist/win-unpacked/`.

## Pubblicazione GitHub

Per distribuire l'app agli utenti finali conviene pubblicare una release GitHub con un archivio della cartella `win-unpacked`, cosi l'utente scarica, estrae e avvia `Ion Security.exe`.

## Nota

Ion Security e una base concreta di difesa locale e monitoraggio reale, ma per una pubblicazione piu professionale servono ancora firma del codice, icona definitiva, policy privacy, test piu ampi e una pipeline release piu robusta.
