# Certificate generator

Creates certificates for a new event and adds them to the portal. Certificates of earlier events are never changed.

## Setup (once)

```
python -m pip install -r tools/requirements.txt
```

## For each event

1. Copy `tools/example/` to `private/<event-name>/` (the `private/` folder is git-ignored).
2. Edit `event.json`: event name, dates, certificate type, wording (`body`), signatories and a 5-character `prefix` for the codes (letters and digits except O, 0, I, 1; different for every event).
   The `body` can use `{name}`, `{event}`, `{date}`, `{team}`, `{college}`, `{usn}`, `{roll}`, `{semester}`, and `<b>…</b>`.
3. Put the participant list in `participants.csv` or `participants.xlsx`. Columns: `name` (required), `usn`, `roll`, `team`, `college`, `semester`, `email`, and optionally `id` to tell apart people with the same name.
4. Preview: `python tools/generate.py private/<event-name>` and check the PDFs in `private/<event-name>/pdf/`.
5. Publish: `python tools/generate.py private/<event-name> --publish`, then commit `data/<PREFIX>.json` and the new files in `certs/`.
   Each event has its own records file named after its code prefix; the portal picks the file from the first five characters of the code.
6. Send each participant their code or download link from `private/<event-name>/codes.csv`.

Re-running keeps the same codes, and unchanged certificates stay byte-for-byte identical, so corrections only add the files that actually changed.
