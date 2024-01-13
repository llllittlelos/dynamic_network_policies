# cilium_client/cilium_client.py

import pathlib
import requests
from configparser import ConfigParser


class CiliumClient:
    def __init__(self, config_file=pathlib.Path(__file__).parent.absolute() / "../config.ini"):
        self.config = self._read_config(config_file)

    @staticmethod
    def _read_config(config_file):
        config = ConfigParser()
        config.read(config_file)

        cluster_section = config["cluster"]
        hosts = [host.strip() for host in cluster_section.get("hosts", "").split(",")]
        port = int(cluster_section.get("port", "64444"))

        return {
            "hosts": hosts,
            "port": port
        }

    def get_hosts(self) -> list:
        return self.config["hosts"]

    def get_endpoints_raw_json(self, host: str = None) -> dict:
        host = host or self.config["hosts"][0]
        endpoint_url = f"http://{host}:{self.config['port']}/endpoints"
        response = requests.get(endpoint_url)
        return response.json()

    def get_services_raw_json(self, host: str = None) -> dict:
        host = host or self.config["hosts"][0]
        services_url = f"http://{host}:{self.config['port']}/services"
        response = requests.get(services_url)
        return response.json()
