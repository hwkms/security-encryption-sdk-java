import json
import requests


class EcsMetadataService:

    METADATA_BASE = "http://169.254.169.254/meta-data/latest/instance-identity"
    DOCUMENT_URL = METADATA_BASE + "/document"
    SIGNATURE_URL = METADATA_BASE + "/signature"

    _cached_instance_id = None

    @classmethod
    def get_ecs_instance_id(cls):
        if cls._cached_instance_id is not None:
            return cls._cached_instance_id
        try:
            doc_str = cls.fetch_identity_document()
            if doc_str is None:
                return None
            doc = json.loads(doc_str)
            cls._cached_instance_id = doc.get("id")
            return cls._cached_instance_id
        except (json.JSONDecodeError, requests.exceptions.RequestException):
            return None

    @classmethod
    def fetch_identity_document(cls):
        return cls._fetch_metadata(cls.DOCUMENT_URL)

    @classmethod
    def fetch_identity_signature(cls):
        return cls._fetch_metadata(cls.SIGNATURE_URL)

    @classmethod
    def _fetch_metadata(cls, url):
        try:
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            return resp.text
        except Exception:
            return None
