# Documentation of CredSweeper

The directory is used for documentation of CredSweeper with using [sphinx](https://www.sphinx-doc.org/en/master/),

## Workflow

There is applied custom documentation, so auto-generation might fail. Please, use auto-generation as reference.
With the command new sources might be updated (in /docs directory):

```bash
sphinx-apidoc --force --full --ext-autodoc ../credsweeper -o source/
```

Edit, then check with command:

```bash
make html
```
