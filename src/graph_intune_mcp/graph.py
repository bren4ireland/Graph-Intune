"""Minimal Microsoft Graph client (app-only auth, paging, throttling retry)."""
import os
import time
from typing import Any, Iterator

import httpx
import msal

GRAPH = "https://graph.microsoft.com"
SCOPE = [f"{GRAPH}/.default"]


class GraphClient:
    def __init__(self) -> None:
        tenant = os.environ["AZURE_TENANT_ID"]
        self._app = msal.ConfidentialClientApplication(
            os.environ["AZURE_CLIENT_ID"],
            authority=f"https://login.microsoftonline.com/{tenant}",
            client_credential=os.environ["AZURE_CLIENT_SECRET"],
        )
        self._http = httpx.Client(timeout=60)

    def _token(self) -> str:
        result = self._app.acquire_token_for_client(scopes=SCOPE)
        if "access_token" not in result:
            raise RuntimeError(f"Graph auth failed: {result.get('error_description', result)}")
        return result["access_token"]

    def get_all(self, path: str, params: dict[str, str] | None = None) -> Iterator[dict[str, Any]]:
        """Yield every item of a paged Graph collection."""
        url: str | None = f"{GRAPH}{path}"
        while url:
            for attempt in range(5):
                r = self._http.get(url, params=params, headers={"Authorization": f"Bearer {self._token()}"})
                if r.status_code in (429, 503):
                    time.sleep(int(r.headers.get("Retry-After", 2 ** attempt)))
                    continue
                break
            r.raise_for_status()
            body = r.json()
            yield from body.get("value", [])
            url, params = body.get("@odata.nextLink"), None

    def encryption_states(self) -> list[dict[str, Any]]:
        # beta-only endpoint with detailed BitLocker/FileVault state
        return list(self.get_all("/beta/deviceManagement/managedDeviceEncryptionStates"))

    def managed_devices(self) -> list[dict[str, Any]]:
        select = ("id,deviceName,userPrincipalName,operatingSystem,osVersion,lastSyncDateTime,"
                  "complianceState,isEncrypted,managementState,model,serialNumber")
        return list(self.get_all("/v1.0/deviceManagement/managedDevices", {"$select": select, "$top": "500"}))
