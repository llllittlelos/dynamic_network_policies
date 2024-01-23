# cilium_client/cilium_client.py

import pathlib
import requests
import yaml
from configparser import ConfigParser


class CiliumClient:
    microservices_cilium_client_data = {}

    def __init__(self, microservices_name: str, force=False):
        current_dir = pathlib.Path(__file__).parent.resolve()
        config_file = current_dir / "../config.ini"
        self.microservices_name = microservices_name
        self.config = self._read_config(config_file)
        self.cilium_client_path = current_dir / f"../output/{self.microservices_name}/cilium_client/"
        checkout = self.check_output_dir()
        if force is not True and checkout is True:
            for host in self.config["hosts"]:
                self.microservices_cilium_client_data[host] = {}
                with open(self.cilium_client_path / host / "endpoints.yaml", "r") as file:
                    self.microservices_cilium_client_data[host]["endpoints"] = yaml.load(file, Loader=yaml.Loader)
                with open(self.cilium_client_path / host / "services.yaml", "r") as file:
                    self.microservices_cilium_client_data[host]["services"] = yaml.load(file, Loader=yaml.Loader)
        else:
            self.microservices_cilium_client_data = self.generate_cilium_client_data()
            for host in self.config["hosts"]:
                host_dir = self.cilium_client_path / host
                if not host_dir.exists():
                    try:
                        host_dir.mkdir(parents=True, exist_ok=True)
                    except Exception as e:
                        print(f"error creating host directory: {e}")

                self.write_to_yaml_file(self.microservices_cilium_client_data[host]["endpoints"],
                                        host_dir / "endpoints.yaml")
                self.write_to_yaml_file(self.microservices_cilium_client_data[host]["services"],
                                        host_dir / "services.yaml")

    def check_output_dir(self) -> bool:
        for host in self.config["hosts"]:
            if not pathlib.Path(self.cilium_client_path / host).is_dir():
                return False

        return True

    @staticmethod
    def write_to_yaml_file(data, filename):
        if data is not None:
            with open(filename, "w") as file:
                yaml.dump(data, file, default_flow_style=False)

    @staticmethod
    def _read_config(config_file) -> dict:
        config = ConfigParser()
        config.read(config_file)

        cluster_section = config["cluster"]
        hosts = [host.strip() for host in cluster_section.get("hosts", "").split(",")]
        port = int(cluster_section.get("port", "64444"))

        return dict(hosts=hosts, port=port)

    def get_hosts(self) -> list:
        return self.config["hosts"]

    def get_endpoints_raw_json(self, host: str = None) -> dict:
        host = host or self.config["hosts"][0]
        endpoint_url = f"http://{host}:{self.config['port']}/endpoints"
        try:
            response = requests.get(endpoint_url)
        except Exception as e:
            print(f"error: {e} while getting endpoints to {host}")
            exit(1)
        return response.json()

    def get_services_raw_json(self, host: str = None) -> dict:
        host = host or self.config["hosts"][0]
        services_url = f"http://{host}:{self.config['port']}/services"
        try:
            response = requests.get(services_url)
        except Exception as e:
            print(f"error: {e} while getting services to {host}")
            exit(1)
        return response.json()

    def generate_cilium_client_data(self):
        cilium_client_data = {}
        for host in self.config["hosts"]:
            cilium_client_data[host] = {}
            cilium_client_data[host]["endpoints"] = self.get_endpoints_raw_json(host)
            cilium_client_data[host]["services"] = self.get_services_raw_json(host)

        return cilium_client_data

    def get_all_endpoints(self):
        endpoints = {}
        for host in self.config["hosts"]:
            endpoints[host] = self.get_endpoints_raw_json(host)
        return endpoints

    def get_all_services(self):
        services = {}
        for host in self.config["hosts"]:
            services[host] = self.get_services_raw_json(host)
        return services
