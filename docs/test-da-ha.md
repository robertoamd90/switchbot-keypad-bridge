# Primo test diagnostico da ESPHome Device Builder in Home Assistant

Questo branch prepara la diagnostica: il collegamento keypad resta CTR.
Il self-test GCM verifica la primitiva sull'ESP32; non abilita GCM sul keypad.

## Primo avvio con ESP32-C3-DevKitM-1

Se non hai ancora uno YAML, usa il file completo
[`switchbot-keypad-bridge.esp32-c3.diagnostics.yaml`](../switchbot-keypad-bridge.esp32-c3.diagnostics.yaml).
Non richiede altri YAML o cartelle locali. Usa ESP-IDF, flash 4 MB e nessuna
PSRAM. Scarica il componente direttamente dal branch diagnostico pubblicato.

Compilazione verificata con ESPHome 2026.10.2: firmware 1.290.814 byte su
1.835.008 byte disponibili per l'applicazione (70,3%); RAM statica dichiarata
132.692 su 321.296 byte (41,3%). Build eseguita con credenziali di esempio e
sorgente locale equivalente al branch pubblicato. Questi numeri non misurano i
picchi di heap durante Wi-Fi, TLS e BLE; la stabilita va verificata sulla scheda.

In ESPHome Device Builder crea un dispositivo con nome
`switchbot-keypad-bridge`, apri il suo editor e sostituisci il contenuto con quel
file. Nei secrets di Device Builder devono essere presenti:

```yaml
wifi_ssid: "NOME_DELLA_TUA_RETE"
wifi_password: "PASSWORD_DELLA_TUA_RETE"
ota_password: "SCEGLI_UNA_PASSWORD_OTA"
```

Usa la prima installazione tramite USB: dal browser sul computer collegato alla
scheda, oppure attraverso l'host HA se la scheda e fisicamente collegata a
quell'host. L'installazione wireless sara disponibile dopo il primo avvio in rete.

Al primo avvio apri i log e cerca `GCM primitive self-test: PASS`. Il bridge
senza keypad associato apre automaticamente il wizard all'indirizzo
`http://<IP-della-scheda>/`: da li accedi al tuo account SwitchBot e associ il
keypad. Non inviare le credenziali SwitchBot in chat e non inserirle nello YAML.
Successivamente esegui i due tentativi di sblocco descritti piu sotto.

## Modifica il dispositivo esistente

Conserva lo YAML funzionante: scheda, flash, PSRAM, rete, nome, API, OTA e
automazioni devono restare quelli del tuo dispositivo. Salva una copia dello
YAML prima delle modifiche. Non importare la configurazione hardware di un'altra
scheda.

1. Nel blocco `external_components` sostituisci la voce relativa al bridge con:

   ```yaml
   external_components:
     - source:
         type: git
         url: https://github.com/robertoamd90/switchbot-keypad-bridge
         ref: feat/keypad-gcm-investigation
       components: [switchbot_keypad_bridge]
       refresh: 0s
   ```

   Conserva eventuali altre voci relative ad altri componenti. Sostituisci la
   sorgente upstream esistente, senza aggiungere una seconda copia del bridge.
   `refresh: 0s` fa controllare il branch a ogni compilazione dei test.

2. Nel blocco `switchbot_keypad_bridge` verifica che ci sia
   `id: keypad_bridge`. Se hai gia un altro ID, usa quello anche nella lambda
   seguente, senza cambiare gli altri riferimenti della tua configurazione.

3. Nel blocco `esphome` aggiungi questo avvio diagnostico. Se esiste gia
   `on_boot`, aggiungi una voce alla sua lista invece di duplicare la chiave:

   ```yaml
   esphome:
     # Conserva qui name e le altre impostazioni esistenti.
     on_boot:
       - priority: -100
         then:
           - lambda: 'id(keypad_bridge).run_crypto_selftest();'
   ```

4. Nel blocco `logger` usa:

   ```yaml
   logger:
     level: DEBUG
     logs:
       switchbot_keypad_bridge: INFO
       switchbot_keypad_bridge.session: DEBUG
   ```

   Conserva baud rate, UART e altre impostazioni eventualmente necessarie sulla
   tua scheda; unisci le voci `logs` gia presenti.

## Compilazione, installazione e prova

In Device Builder apri il dispositivo, valida la configurazione e usa il comando
di installazione con il metodo che usi abitualmente (wireless se OTA e gia
funzionante). Non serve una cartella `components` su Home Assistant.

Apri i log; se ti colleghi dopo l'avvio, riavvia l'ESP32 con il suo pulsante
fisico o togli/ridai alimentazione per vedere il self-test. Non usare l'entita
Home Assistant **Reset** del bridge: quella cancella le associazioni e ruota la
chiave.

Raccogli:

1. La riga `GCM primitive self-test: PASS` oppure `FAIL`.
2. Uno sblocco con una credenziale gia registrata e l'evento corrispondente.
3. Dopo 25 secondi, un secondo sblocco con la stessa credenziale.
4. Modello/firmware del keypad, modello ESP32 ed eventuale serratura collegata.
5. Le righe di handshake, contesto, disconnessione ed eventuali errori durante
   questi tentativi. Oscura nomi, MAC e indici credenziale prima di condividere.

Il risultato atteso e self-test PASS e funzionamento CTR come prima. Se il
self-test fallisce, il problema si trova nel backend GCM della scheda. Se passa,
possiamo concentrarci sul protocollo e preparare il test successivo in base
all'hardware presente. Questo primo test non prova che il keypad accetti GCM.

## Tornare alla versione precedente

Ripristina lo YAML salvato e compila/installa con la sorgente originale. Non
premere Reset e non cancellare NVS: questo branch non richiede un nuovo pairing.

## Configurazione completa di esempio

`switchbot-keypad-bridge.diagnostics.yaml` e un esempio completo per
**Seeed XIAO ESP32-S3, flash 8 MB e PSRAM octal**, con i tre secret dell'esempio
originale. Per un dispositivo gia funzionante, i quattro cambi sopra sono
preferibili per mantenere la sua configurazione.
