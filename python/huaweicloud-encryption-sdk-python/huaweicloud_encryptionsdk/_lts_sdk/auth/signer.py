import datetime
import hashlib
import hmac
from typing import List
from urllib.parse import unquote, quote

import requests
from huaweicloud_encryptionsdk._lts_sdk.producer.lts_http.simple_request import LtsRequest


class Constants:
    HEADER_X_DATA = "X-Sdk-Date"
    BASIC_DATE_FORMAT = "%Y%m%dT%H%M%SZ"
    DERIVED_DATE_FORMAT = "%Y%m%d"
    HEADER_CONTENT_SHA256 = "X-Sdk-Content-Sha256"
    AUTH_SERVICE_NAME = "lts"
    ALGORITHM = "V11-HMAC-SHA256"
    HEADER_AUTHORIZATION = "Authorization"


class Signer(object):

    def __init__(self):
        self._hash_func = hashlib.sha256

    def _derive_key(self, ak, sk, info):
        salt = bytearray(ak, 'utf-8')
        ikm = bytearray(sk, 'utf-8')
        info_bytes = bytearray(info, 'utf-8')
        prk = hmac.new(salt, ikm, self._hash_func).digest()
        okm = b""
        t = b""
        for i in range(1, (32 + 32) // 32 + 1):
            t = hmac.new(prk, t + info_bytes + bytes([i]), self._hash_func).digest()
            okm += t
        return okm[:32].hex()

    def sign(self, lts_request: LtsRequest) -> requests.Request:
        try:
            if lts_request.method not in {"POST", "PATCH", "PUT"}:
                lts_request.body = ""

            if lts_request.security_token:
                lts_request.headers["X-Security-Token"] = lts_request.security_token

            date_time = datetime.datetime.now(datetime.timezone.utc)
            if Constants.HEADER_X_DATA not in lts_request.headers:
                lts_request.headers[Constants.HEADER_X_DATA] = date_time.strftime(Constants.BASIC_DATE_FORMAT)
            else:
                time = lts_request.headers[Constants.HEADER_X_DATA]
                date_time = datetime.datetime.strptime(time, Constants.BASIC_DATE_FORMAT)

            signed_headers = self._signed_headers(lts_request)
            canonical_request = self._canonical_request(lts_request, signed_headers)
            date_str = datetime.datetime.strftime(date_time, Constants.DERIVED_DATE_FORMAT)
            info_str = "%s/%s/%s" % (date_str, lts_request.region, Constants.AUTH_SERVICE_NAME)
            string_to_sign = self._string_to_sign_derived(canonical_request, date_time, info_str)
            derivation_key = self._derive_key(lts_request.ak, lts_request.sk, info_str)
            signature = self._sign_string_to_sign(string_to_sign, derivation_key)
            auth_value = self._derivation_auth_header_value(signature, lts_request.ak, signed_headers, info_str)
            lts_request.headers[Constants.HEADER_AUTHORIZATION] = auth_value

            url = lts_request.host + lts_request.interface
            req = requests.Request(method=lts_request.method, headers=lts_request.headers, data=lts_request.body,
                                   url=url, params=lts_request.query)
            return req
        except Exception as e:
            pass

    def _hash_hex_string(self, data):
        # type: (bytes) -> str
        _hash = self._hash_func(data)
        return _hash.hexdigest()

    @classmethod
    def _signed_headers(cls, lts_request: LtsRequest):
        key_list = []
        for key, value in lts_request.headers.items():
            key_list.append(key.lower())
        key_list.sort()
        return key_list

    @classmethod
    def _canonical_headers(cls, request: LtsRequest, signed_headers: List[str]):
        canonical_headers = []
        __headers = {}
        for key in request.headers:
            key_encoded = key.lower()
            value = request.headers[key]
            value_encoded = str(value).strip()
            __headers[key_encoded] = value_encoded

        for key in signed_headers:
            canonical_headers.append(key + ":" + __headers.get(key))

        return '\n'.join(canonical_headers) + "\n"

    @classmethod
    def _canonical_uri(cls, lts_request: LtsRequest):
        pattens = unquote(lts_request.interface).split("/")
        uri = []
        for v in pattens:
            uri.append(cls._url_encode(v))
        url_path = "/".join(uri)

        if url_path[-1] != '/':
            url_path = url_path + "/"

        return url_path

    @classmethod
    def _url_encode(cls, s):
        return quote(s, safe='~')

    @classmethod
    def _canonical_query_string(cls, lts_request: LtsRequest):
        query_keys = []
        for key, value in lts_request.query.items():
            query_keys.append(key)
        query_keys.sort()
        canonical_query_param = []

        for query_key in query_keys:
            encode_query_key = cls._url_encode(query_key)
            query_value = lts_request.query[query_key]
            if isinstance(query_value, str):
                kv = "%s=%s" % (encode_query_key, cls._url_encode(query_value))
                canonical_query_param.append(kv)
            elif isinstance(query_value, bool):
                kv = "%s=%s" % (encode_query_key, cls._url_encode(str(query_value).lower()))
                canonical_query_param.append(kv)
            elif isinstance(query_value, int):
                kv = "%s=%s" % (encode_query_key, cls._url_encode(str(query_value)))
                canonical_query_param.append(kv)
        return '&'.join(canonical_query_param)

    def _canonical_request(self, lts_request: LtsRequest, signed_headers: List[str]):
        hex_encode = ""
        if Constants.HEADER_CONTENT_SHA256 in signed_headers:
            hex_encode = lts_request.headers[Constants.HEADER_CONTENT_SHA256]
        else:
            hex_encode = self._hash_hex_string(lts_request.body.encode('utf-8'))

        canonical_uri = self._canonical_uri(lts_request)
        canonical_query_string = self._canonical_query_string(lts_request)
        canonical_headers = self._canonical_headers(lts_request, signed_headers)

        return "{0}\n{1}\n{2}\n{3}\n{4}\n{5}".format(lts_request.method.upper(), canonical_uri, canonical_query_string,
                                                     canonical_headers,
                                                     ";".join(signed_headers), hex_encode)

    def _string_to_sign_derived(self, canonical_request, time, info=None):
        # type: (str, datetime, str) -> str
        return "%s\n%s\n%s\n%s" % (
            Constants.ALGORITHM,
            datetime.datetime.strftime(time, Constants.DERIVED_DATE_FORMAT),
            info,
            self._hash_hex_string(canonical_request.encode('utf-8')))

    def _sign_string_to_sign(self, string_to_sign, key):
        # type: (str, str) -> str
        return self._hex(self._hmac(key.encode('utf-8'), string_to_sign.encode('utf-8')))

    def _derivation_auth_header_value(self, signature, app_key, signed_headers, info=None):
        # type: (str, str, list, str) -> str
        return "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
            Constants.ALGORITHM, app_key, info, ";".join(signed_headers), signature)

    def _hex(self, data):
        return data.hex()

    def _hmac(self, key, data):
        # type: (bytes, bytes) -> bytes
        return hmac.new(key, data, digestmod=self._hash_func).digest()
