#!/usr/bin/env python3
import configparser
import json
import os
import sys
import logging
from argparse import ArgumentParser
from requests import Session

# Path of the configuration file.
CONFIG_PATH = os.path.abspath("config.ini")

# API endpoint for DigitalOcean
API_ENDPOINT = "https://api.digitalocean.com/v2"

# Required configuration items that, if missing or empty, will cause failure
REQUIRED_CONFIG_OPTIONS = [
    ['CONFIG', 'DigitalOceanToken'],
    ['DOMAIN', 'Domain']
]

LOG_LEVELS = {
    "debug": 10,
    "info": 20,
    "warning": 30,
    "error": 40,
    "off": -1
}


def get_config() -> configparser.ConfigParser:
    parser = configparser.ConfigParser()

    try:
        parser.read(CONFIG_PATH)
    except FileNotFoundError:
        logging.fatal(f"Failed to load config file: config file not found: {CONFIG_PATH}")
        sys.exit(1)

    for option in REQUIRED_CONFIG_OPTIONS:
        if not parser.has_option(option[0], option[1]) or parser.get(option[0], option[1]) == '':
            logging.fatal(f"Failed to load config file: missing {option[0]}.{option[1]} option")
            sys.exit(1)

    logging.debug(f"Log file loaded with {len(parser.items())} entries.")
    return parser


def setup_session(api_token: str) -> Session:
    session = Session()
    session.headers.update({
        "Authorization": f"Bearer {api_token}"
    })

    logging.debug(f"Network session created")

    return session


def get_records(session: Session, domain: str, subdomains: list[str], include_domain: bool,
                include_subdomain: bool) -> list:
    request = session.get(f"{API_ENDPOINT}/domains/{domain}/records")
    request_list = list()

    if include_subdomain:
        request_list += subdomains

    if include_domain:
        request_list.append('@')

    logging.debug(f"Requesting domain records for names {request_list}")

    if request.status_code == 200:
        response = request.json()
        response_records = list(response['domain_records'])

        return [r for r in response_records if r['type'] == 'A' and r['name'] in subdomains]
    else:
        raise Exception(f"get_records(): request failed: {request.json()}")


def get_ip() -> str:
    request = Session().get("https://api.ipify.org?format=json")

    if request.status_code == 200:
        ip = request.json()['ip']
        logging.info(f"Found IP address {ip}")
        return ip
    else:
        logging.error(f"Failed to get IP address: {request.json()}")
        raise Exception(f"get_ip(): request failed: {request.json()}")


def set_records(session: Session, ip: str, domain: str, records: list):
    logging.info(f"Performing record update with new IP {ip} on {len(records)} record(s).")

    for record in records:
        record_id = record['id']
        record_name = record['name']
        record_ip = record['data']
        record_name_fq = f"{record_name}.{domain}"

        if record_ip == ip:
            logging.info(f"Skipping record {record_name_fq} as IP address is already set to {ip}")
        else:
            logging.info(f"Requesting record update for {record_name_fq}")
            request = session.put(f"{API_ENDPOINT}/domains/{domain}/records/{record_id}", json.dumps({
                'data': ip
            }))

            if request.status_code == 200:
                logging.info(f"Successfully set {record_name_fq} to {ip}")
            else:
                logging.error(f"Failed to set record {record_name_fq}: {request.json()}")


if __name__ == '__main__':
    c = get_config()

    c_log_level = c.get('CONFIG', 'LogLevel', fallback='info')
    c_log_file = c.get('CONFIG', 'LogFile', fallback='dyndns.log')

    if c_log_level not in LOG_LEVELS:
        logging.fatal(f"Unable to initialise logging: log level defined does not exist")
        sys.exit(1)

    if c_log_file != 'off':
        logging.basicConfig(
            level=LOG_LEVELS[c_log_level],
            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s'
        )
        logging.debug(f"Logging configured without log file at logging level {c_log_level} ({LOG_LEVELS[c_log_level]})")
    else:
        logging.basicConfig(
            level=LOG_LEVELS[c_log_level],
            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
            filename=c_log_file,
            filemode='a'
        )
        logging.debug(
            f"Logging configured with log file {c_log_file} at logging level {c_log_level} ({LOG_LEVELS[c_log_level]})")

    logging.debug("Logging configured.")

    logging.debug("debug")
    logging.info("info")
    logging.warning("warning")
    logging.error("error")
    logging.fatal("fatal")

    c_api_token = c.get('CONFIG', 'DigitalOceanToken')
    c_domain = c.get('DOMAIN', 'Domain')
    c_domain_update = c.getboolean('DOMAIN', 'DomainUpdate', fallback=True)
    c_subdomains = c.get('DOMAIN', 'SubDomains', fallback='').split()
    c_subdomain_update = c.get('DOMAIN', 'SubDomainUpdate', fallback=True)

    s = setup_session(c_api_token)
    s.headers.update({
        "Authorization": f"Bearer {c.get('CONFIG', 'DigitalOceanToken')}"
    })

    domain_records = get_records(s, c_domain, c_subdomains, c_domain_update, c_subdomain_update)
    new_ip = get_ip()

    set_records(s, new_ip, c_domain, domain_records)
