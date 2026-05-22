"""
Optional Microsoft Graph collector starter.

This module is intentionally defensive and read-only. The demo project uses CSV files by default.
For a real tenant, register an app in Microsoft Entra ID, grant the least required permissions,
create a client secret, store values in .env, then call Microsoft Graph endpoints.
"""

import os
from typing import Dict, List

import msal
import requests
from dotenv import load_dotenv

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


class Microsoft365GraphCollector:
    def __init__(self) -> None:
        load_dotenv()
        self.tenant_id = os.getenv("MS_TENANT_ID")
        self.client_id = os.getenv("MS_CLIENT_ID")
        self.client_secret = os.getenv("MS_CLIENT_SECRET")
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            raise ValueError("Missing MS_TENANT_ID, MS_CLIENT_ID or MS_CLIENT_SECRET in .env")

    def get_token(self) -> str:
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=authority,
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            raise RuntimeError(f"Could not obtain Graph token: {result}")
        return result["access_token"]

    def list_users(self) -> List[Dict]:
        token = self.get_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{GRAPH_BASE_URL}/users?$select=id,displayName,userPrincipalName,accountEnabled,userType"
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json().get("value", [])

    def list_user_authentication_methods(self, user_id: str) -> List[Dict]:
        token = self.get_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{GRAPH_BASE_URL}/users/{user_id}/authentication/methods"
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json().get("value", [])
