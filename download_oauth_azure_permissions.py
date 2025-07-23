import re
import requests
import json

RAW_URL = (
    "https://raw.githubusercontent.com/"
    "microsoftgraph/microsoft-graph-docs-contrib/main/"
    "concepts/permissions-reference.md"
)


def parse_permissions(md_text):
    """
    Parses the Microsoft Graph permissions-reference.md content into a sequence of dicts.
    Each dict contains:
      - permission: permission name
      - application_guid: GUID or None
      - delegated_guid: GUID or None
      - display_app, display_del: DisplayText strings
      - description_app, description_del: Description strings
      - admin_consent_application, admin_consent_delegated: booleans
    """
    # Split by each permission header (### PermissionName)
    blocks = re.split(r"^### ", md_text, flags=re.MULTILINE)[1:]

    for block in blocks:
        lines = block.splitlines()
        # First line is permission name
        permission = lines[0].strip()
        # Initialize row vars
        app_guid = del_guid = display_app = display_del = None
        desc_app = desc_del = None
        admin_app = admin_del = False

        # Iterate lines to find table rows
        for line in lines:
            cols = [c.strip() for c in line.split("|")][1:-1]
            if not cols or len(cols) < 3:
                continue
            row_header = cols[0]
            if row_header == "Identifier":
                app_guid = cols[1]
                del_guid = cols[2]
            elif row_header == "DisplayText":
                display_app = cols[1]
                display_del = cols[2]
            elif row_header == "Description":
                desc_app = cols[1]
                desc_del = cols[2]
            elif row_header == "AdminConsentRequired":
                admin_app = cols[1].lower() == "yes"
                admin_del = cols[2].lower() == "yes"

        yield {
            "permission": permission,
            "application_guid": app_guid,
            "delegated_guid": del_guid,
            "display_application": display_app,
            "display_delegated": display_del,
            "description_application": desc_app,
            "description_delegated": desc_del,
            "admin_consent_application": admin_app,
            "admin_consent_delegated": admin_del,
        }


def main(output_path="permissions.jsonl"):
    # Fetch raw markdown
    resp = requests.get(RAW_URL)
    resp.raise_for_status()
    md = resp.text

    # Parse and write JSONL
    entries = list(parse_permissions(md))
    with open(output_path, "w", encoding="utf-8") as fout:
        for entry in entries:
            fout.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"Generated {len(entries)} entries to {output_path}")


if __name__ == "__main__":
    main()
