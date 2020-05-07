import boto3
import clamd
import requests

from . import logging

logger = logging.get_logger()


def get_client(access_key, secret_key, endpoint, region):
    session = boto3.session.Session(access_key, secret_key, region_name=region)
    return session.client('s3', endpoint_url=endpoint)


def scan_obj(file_obj, clamav_host):
    c = clamd.ClamdNetworkSocket(clamav_host)
    c.instream(file_obj)


def scan_url(url, clamav_host, session=None):
    session = session or requests.Session()
    with session.get(url, stream=True) as r:
        r.raise_for_status()
        scan_obj(r.raw, clamav_host)


def scan_s3(bucket, key, client, clamav_host):
    try:
        scan_obj(client.get_object(Bucket=bucket, key=key)['Body'], clamav_host)
    except Exception as e:
        logger.exception('Scan failed: %s', e)
        raise e
