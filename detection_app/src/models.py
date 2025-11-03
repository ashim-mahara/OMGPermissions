from dataclasses import dataclass
from typing import List


@dataclass
class UserConsent:
    user_id: str
    user_principal_name: str
    user_display_name: str
    app_id: str
    resource_id: str
    scope: str


@dataclass
class ApplicationSummary:
    app_id: str
    display_name: str
    permissions: List[str]
    users: List[str]
