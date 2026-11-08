# Published regression fixtures

These copies are required by the existing offline tests. The CI runner maps them
into their historical relative paths in its disposable workspace.

- flask-step2-integrated.json: saved STEP 2 Flask output; Windows absolute paths
  replaced by relative paths or executable basename. Six graph nodes unchanged.
- mixed-resolved.json: saved STEP 4 synthetic mixed fixture output; source paths
  made repository-relative. All 22 packages and declarations unchanged.
- mixed.cdx.json: byte-identical STEP 4 synthetic SBOM.

Original local results were preserved and are not published. Added publication_note
only labels the two normalized JSON copies; it is not a new parsing result.
These fixtures are not proof of installed packages or real vulnerabilities.
