import json


def is_present(value):
    """Return True if the GUID/string is a real value (not '-', '', None)."""
    return value not in (None, "", "-", "null")


def count_permission_types(jsonl_path):
    both = 0
    delegated_only = 0
    application_only = 0

    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            entry = json.loads(line)

            has_delegated = is_present(entry.get("delegated_guid"))
            has_application = is_present(entry.get("application_guid"))

            if has_delegated and has_application:
                both += 1
            elif has_delegated and not has_application:
                delegated_only += 1
            elif has_application and not has_delegated:
                application_only += 1

    return {
        "both": both,
        "delegated_only": delegated_only,
        "application_only": application_only,
    }


if __name__ == "__main__":
    path = "permissions.jsonl"  # change this
    counts = count_permission_types(path)

    print("=== Permission Type Counts ===")
    print(f"Both delegated + application: {counts['both']}")
    print(f"Delegated only:              {counts['delegated_only']}")
    print(f"Application only:            {counts['application_only']}")
