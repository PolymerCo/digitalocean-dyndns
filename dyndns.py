#!/usr/bin/env python3
import json

from requests import Session

API_ENDPOINT = "https://api.digitalocean.com/v2"


def setup_session(api_token: str) -> Session:
    session = Session()
    session.headers.update({
        "Authorization": f"Bearer {api_token}"
    })

    return session


def get_records(session: Session, domain: str, subdomains: list[str]) -> list:
    request = session.get(f"{API_ENDPOINT}/domains/{domain}/records")
    subdomains.append('@')

    if request.status_code == 200:
        response = request.json()
        response_records = list(response['domain_records'])

        return [r for r in response_records if r['type'] == 'A' and r['name'] in subdomains]
    else:
        raise Exception(f"get_records(): request failed: {request.json()}")


def get_ip(session: Session) -> str:
    request = session.get("https://api.ipify.org?format=json")

    if request.status_code == 200:
        return request.json()['ip']
    else:
        raise Exception(f"get_ip(): request failed: {request.json()}")


def set_records(ip: str, domain: str, records: list):
    for record in records:
        record_id = record['id']
        record_name = record['name']

        request = r_session.put(f"{API_ENDPOINT}/domains/{domain}/records/{record_id}", json.dumps({
            'data': ip
        }))

        if request.status_code == 200:
            print(f"successfully set {record_name}.{domain} to {ip}")
        else:
            print(f"set_records(): failure setting ${record_name}.{domain}: {request.json()}")


if __name__ == '__main__':
    s = setup_session()
    r_session.headers.update({
        "Authorization": f"Bearer {API_TOKEN}"
    })

domain_records = get_records(DOMAIN, SUB_DOMAINS)
new_ip = get_ip()
set_records("0.0.0.0", DOMAIN, domain_records)
