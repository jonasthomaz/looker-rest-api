#!/usr/bin/env python

"""Let's audit Data Studio resources and permissions!"""

import logging
import os.path
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

import requests

from oauth2client.service_account import ServiceAccountCredentials

from google import auth

MODULE_DIRECTORY = Path(os.path.dirname(os.path.realpath(__file__)))
CREDENTIALS_PATH = MODULE_DIRECTORY / "service-account-key.json"
API_BASE = "https://datastudio.googleapis.com/v1"
REPORTS_ENDPOINT = f"{API_BASE}/assets:search?assetTypes=REPORT"
# PERMISSIONS_ENDPOINT = f"{API_BASE}/assets/{assetId}/permissions"
SCOPES = [
    "https://www.googleapis.com/auth/datastudio.readonly",
    "https://www.googleapis.com/auth/datastudio",
]

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DataStudioReport:
    report_id: str
    title: str
    asset_type: str
    owner: str

    @classmethod
    def from_json(cls, report_json: dict) -> "DataStudioReport":
        return cls(
            report_id=report_json["name"],
            title=report_json["title"],
            asset_type=report_json["assetType"],
            owner=report_json["owner"],
        )


def get_service_account_credentials(
        credentials_path: Path,
        scopes: List[str],
        delegated_user: str = None,
) -> ServiceAccountCredentials:
    """Handles loading service account credentials."""
    creds = ServiceAccountCredentials.from_json_keyfile_name(
        credentials_path, scopes=scopes
    )
    if delegated_user is not None:
        creds = creds.create_delegated(delegated_user)

    log.info("Valid credentials acquired.")
    return creds


def main() -> None:
    reports = set()

    username = "chancedegloria@appspot.gserviceaccount.com"
    log.info("Authorizing service account")
    creds = get_service_account_credentials(
        "credencial.json",
        SCOPES,
        delegated_user=username,
    )
    log.info(f"Credentials acquired for {username}")
    token = creds.get_access_token()

    log.info("Requesting reports")
    resp = requests.get(
        REPORTS_ENDPOINT,
        headers={"Authorization": f"Bearer {token.access_token}"},
    )
    log.info(resp.content)
    for report_json in resp.json().get("assets", []):
        reports.add(DataStudioReport.from_json(report_json))

    log.info(f"Retrieved reports")
    for report in reports:
        log.info(f" * {report.title}")


if __name__ == "__main__":
    sys.exit(main())
