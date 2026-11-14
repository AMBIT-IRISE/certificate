# AMBIT-IRISE Certificate Portal

Live at https://ambit-irise.github.io/certificate/

Certificate verification and download portal of AMBIT-IRISE Foundation, AMBIT Belagavi.

- `index.html`: verify a certificate (`?id=CERTIFICATE-CODE`, opened by the QR code)
- `download.html`: students download their certificate with their code (`?code=CERTIFICATE-CODE`)
- `data/<PREFIX>.json`: certificate records of one event, named after the first five characters of its codes (for example `data/B4B26.json`), each record encrypted with its own certificate code
- `tools/`: generator for new events (see `tools/README.md`)
- `certs/`: certificate PDFs, each encrypted with its own certificate code
- `assets/`: logos

No personal data is readable in this repository without the corresponding certificate code.
