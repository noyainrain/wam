# wam!

Web application manager.

## Requirements

* Python >= 3.4

## Installing dependencies

```sh
pip install --user -U -r requirements.txt
```

## Test

```sh
python3 -m unittest discover -v
```

## Web App Meta

* `download`: Git URL to the application code.
* `extension_path`: Path to.. Defaults to `'ext'`.
* `default_extensions`: List of Git URLs of extensions that should be added by default. Defaults to
  `[]`.
