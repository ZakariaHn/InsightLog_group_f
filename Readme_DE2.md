# InsightLog

InsightLog ist ein Python-Skript zum Extrahieren und Analysieren von Daten aus Server-Logdateien (Nginx, Apache2 und Auth-Logs). Es stellt Werkzeuge zum Filtern, Parsen und Analysieren gängiger Server-Logformate bereit.

## Funktionen

- Filtern von Logdateien nach Datum, IP-Adresse oder benutzerdefinierten Mustern
- Extrahieren von Webanfragen und Authentifizierungsversuchen aus Logdateien
- Analyse von Logs aus Nginx, Apache2 und System-Auth-Logs

## Installation

Klone dieses Repository:
```bash
git clone https://github.com/CyberstepsDE/insightlog.git
cd insightlog
````

Du bist startklar!

## Verwendung über die Kommandozeile

Du kannst den Analyzer über die CLI ausführen:

```bash
python3 insightlog.py --service nginx --logfile logs-samples/nginx1.sample --filter 192.10.1.1
```

Weitere Beispiele:

* Analyse von Apache2-Logs für eine bestimmte IP:

```bash
python3 insightlog.py --service apache2 --logfile logs-samples/apache1.sample --filter 127.0.1.1
```

* Analyse von Auth-Logs nach einer bestimmten Zeichenkette:

```bash
python3 insightlog.py --service auth --logfile logs-samples/auth.sample --filter root
```

* Analyse aller Nginx-Logeinträge (kein Filter):

```bash
python3 insightlog.py --service nginx --logfile logs-samples/nginx1.sample
```

## Bekannte Fehler

Siehe [KNOWN_BUGS.md](KNOWN_BUGS.md) für eine Liste der aktuellen Fehler und Hinweise zur Reproduktion.

## Geplante Funktionen

Siehe [ROADMAP.md](ROADMAP.md) für geplante Funktionen und Verbesserungen.

## Tests ausführen

Für Tests verwenden wir das in Python integrierte `unittest`-Modul. Um die Tests auszuführen:

```bash
python3 -m unittest discover -s tests -v
```

## Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert. Siehe [LICENSE](LICENSE) für weitere Details.

```
```
