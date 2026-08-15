# PII attachment anonymizer

Creates a separate, mirrored folder tree containing pseudonymized copies of files.
It does not change the originals.

## Input and output folders

Put source documents under the included `input/` folder. You may create any nested
folders beneath it, including customer or case folders. The tool recreates every
directory (including empty ones) under `output/` in the same relative position.
Every folder name and filename is passed through the same anonymization rules as
document contents. Only names listed in your config are renamed; unconfigured
folder names are retained so the structure stays the same.

```
input/Anthony Romello Ltd/2025/Anthony Romello Ltd invoice.xlsx
output/C-1576/2025/C-1576 invoice.xlsx
```

## Supported files

- DOCX, XLSX/XLSM, PPTX (body content, common headers/tables, and document metadata)
- Searchable PDFs (text PII is redacted; scanned/image-only text must be OCR'd first)
- CSV/TSV, TXT, MD, JSON, XML, HTML

It detects email addresses, phone numbers, Canadian SIN-like values, payment-card-like values, and IPv4 addresses.  Entity and name variations should be explicitly listed in the config: fully automatic name/address detection is not reliable enough for safe release.

## Install

```bash
cd ~/Desktop/pii_anonymizer
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m spacy download en_core_web_sm
brew install tesseract
```

## Configure company and personal-name replacements

Copy `entity_config.example.json`, then add each entity key and every known spelling/abbreviation. Use `companies` for company names; use `people`, `first_names`, and `last_names` for personal names. Include full names **and** standalone first/last names, because a filename or title may contain only one part of a person's name.

The longest matching variant is replaced first, so `Anthony Romello` and a standalone `Anthony` or `Romello` are always caught, each resolving to its own entity.

```json
{
  "people": { "Person One": ["Anthony Romello", "A. Romello"] },
  "first_names": { "First Name One": ["Anthony", "Tony"] },
  "last_names": { "Last Name One": ["Romello", "Ramelo"] },
  "companies": { "Company Limited One": ["Anthony Romello Ltd"] }
}
```

**The JSON key (`Person One`, `Company Limited One`, …) is never the text written into the output.** It only seeds a short, stable code — for example `P-2dc7` or `C-1576` — that every listed variant resolves to. That code is what actually appears in filenames, folder names, document content, and PDFs; the key stays as your own readable reference in this file and in the reverse mapping, so you can look up `Company Limited One -> C-1576` when reviewing output. This keeps a single entity looking identical everywhere, including inside PDFs, without needing a separate abbreviated form.

Add each customer-folder name to the config when it contains a company or personal name that must be anonymized.

## Run

```bash
export PII_ANON_SECRET='store-this-secret-safely-for-repeatable-output'
.venv/bin/python anonymize_attachments.py input output --config entity_config.json
```

To replace a prior output folder on a repeat run, add `--overwrite-output`:

```bash
.venv/bin/python anonymize_attachments.py input output --config entity_config.json --overwrite-output
```

This permanently removes the existing `output/` contents before creating the new anonymized copy.

The output contains:

- `reverse_mapping.json`: plain, readable original-to-pseudonym mapping. It contains every real name, email, phone number, and other PII value found in the source batch, so treat it with the same care as the original documents -- store and share it only as your security process allows.
- `anonymization_audit.json`: file status report, with no reverse mapping

## Automatic name detection

Before writing output, the tool uses a local spaCy model to detect unknown people
and organizations throughout the input batch, including supported document text and
paths. To limit false replacements, it only auto-replaces full personal names and
organizations with a strong company cue (such as `Ltd`, `Inc.`, `LLC`, `Bank`, or
`Holdings`). It assigns stable `P-xxxx` / `C-xxxx` style codes; explicit entries in
`entity_config.json` take precedence over auto-detection.

A detection that is just a longer or shorter spelling of an entity already known —
for example spaCy finding "Apple Inc" in a document body when `Apple` is configured,
or in two documents where the same unconfigured organization appears once as
"Anthropic" and once as "Anthropic PBC" — reuses that entity's existing code rather
than minting an unrelated one, so one real-world company or person never ends up
split across two different codes. This matching only merges within the same kind of
entity (organization with organization, person with person).

Every immediate subfolder of `input/` is also treated as a company name by design.
For example, `input/Anthropic/` becomes an anonymized company folder even when
`Anthropic` is not listed in the config. This convention applies only at the first
folder level; deeper folder names use the conservative rules above.

Named-entity detection cannot reliably distinguish a customer from a supplier or
other organization, so it anonymizes all eligible detected organizations. Bare
company names such as `Apple` should be added to the explicit config. Review the
output and audit before release. Use `--no-auto-detect-names` only when you
deliberately want to rely solely on the explicit mapping configuration.

## Images and scanned PDFs

PNG, JPEG, TIFF, and WebP files are supported. The tool uses local Tesseract OCR
to find configured and automatically detected names, then permanently paints over
the matching image pixels and removes image metadata. PDF pages containing images
are OCR'd too, and matched regions are redacted from the embedded image pixels.
OCR can miss low-resolution, handwritten, stylized, or rotated text, so visually
review every image/scanned PDF before release.

Do not use `--copy-unsupported` for material intended for disclosure: it copies those files unchanged.

## Mandatory QA before release

Review `anonymization_audit.json`, visually inspect random documents from every file type, search output for known customer/entity variants, and confirm all scanned PDFs were OCR'd then re-run. PDF redaction handles recognized searchable text but cannot remove PII embedded in images.

The run stops with a failure entry in the audit if two different source files would become the same anonymized path; this prevents accidental overwrites.

## Running the code

~/Desktop/pii_anonymizer

.venv/bin/python anonymize_attachments.py input output \
  --config entity_config.json \
  --overwrite-output
