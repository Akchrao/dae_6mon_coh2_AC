"""CAN EHR status API — serverless function secured with a managed identity.

No connection strings or keys: storage access uses the function's
user-assigned managed identity, granted a single role on a single storage account.
"""
import json
import logging
import os

import azure.functions as func
from azure.identity import ManagedIdentityCredential
from azure.storage.blob import BlobServiceClient

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

ACCOUNT = os.environ["REFERRALS_STORAGE_ACCOUNT"]
CONTAINER = os.environ.get("REFERRALS_CONTAINER", "referrals")
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]


@app.route(route="ehr-status", methods=["GET"])
def ehr_status(req: func.HttpRequest) -> func.HttpResponse:
    credential = ManagedIdentityCredential(client_id=CLIENT_ID)
    blobs = BlobServiceClient(f"https://{ACCOUNT}.blob.core.windows.net", credential=credential)
    try:
        count = sum(1 for _ in blobs.get_container_client(CONTAINER).list_blobs())
        body = {"service": "CAN EHR status", "status": "ok",
                "auth": "managed-identity", "referrals_container": CONTAINER, "referral_count": count}
        return func.HttpResponse(json.dumps(body), mimetype="application/json", status_code=200)
    except Exception as exc:  # don't leak internals to the caller
        logging.exception("Storage access failed")
        return func.HttpResponse(json.dumps({"status": "error", "error": type(exc).__name__}),
                                 mimetype="application/json", status_code=502)
