# bw-export
Exports a Bitwraden database into an XML file conforming to KeePass 2 XML Format.

The advantage of the XML format, is that it supports importing custom fields from Bitwarden into their own custom fields in KeePass 2, which is not currently supported in the Bitwarden CSV import function.

## Usage

* Log into bw
```bash
bw login
```

* Export xml
```bash
python bw_export_kp.py > passwords.xml
```

* Import the passwords.xml file into KeePass 2 (or other KeePass clones that support importing KeePass2 XML formats)

* delete passwords.xml

## References:
- Bitwarden CLI: https://help.bitwarden.com/article/cli/
- KeePass 2 XML: https://github.com/keepassxreboot/keepassxc-specs/blob/master/kdbx-xml/rfc.txt