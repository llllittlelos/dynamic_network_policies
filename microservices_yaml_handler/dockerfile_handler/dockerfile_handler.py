# microservices_yaml_handler/dockerfile_handler/dockerfile_handler.py

import copy
import json
import pathlib
import requests
import yaml
from configparser import ConfigParser

DSO_GRAPH_API = "https://api.dso.docker.com/v1/graphql"

DSO_GET_PACKAGES_PAYLOAD = \
    {
        'query': 'query web_ImagePackagesByDigest($digest: String!, $context: Context!)\n{\n  imagePackagesByDigest('
                 'context: $context, digest: $digest) {\n    digest\n    imageLayers {\n      layers {\n        '
                 'diffId\n        ordinal\n      }\n    }\n    imagePackages {\n      packages {\n        package {\n '
                 '         purl\n        }\n        locations {\n          diffId\n          path\n        }\n      '
                 '}\n    }\n  }\n}\n',
        'variables': {
            'digest': 'sha256:abc',
            'context': {},
        },
    }

DSO_GET_VULN_PAYLOAD = \
    {
        "query": "\nquery web_VulnerabilitiesByPackage($packageUrls: [String!]!, $context: Context!) {\n  "
                 "vulnerabilitiesByPackage(context: $context, packageUrls: $packageUrls) {\n    purl\n    "
                 "vulnerabilities"
                 "{\n      cvss {\n        score\n        severity\n      }\n      cwes {\n        cweId\n        "
                 "description\n      }\n      description\n      fixedBy\n      publishedAt\n      source\n      "
                 "sourceId\n      vulnerableRange\n    }\n  }\n}\n",
        "variables": {
            "packageUrls": [],
            "context": {}
        }
    }


def read_config(config_file) -> dict:
    config = ConfigParser()
    config.read(config_file)
    docker_hub_section = config["docker_hub"]
    _username = str(docker_hub_section.get("username"))
    _password = str(docker_hub_section.get("password"))

    return dict(username=_username, password=_password)


def get_docker_hub_token(username, password):
    auth_url = "https://hub.docker.com/v2/users/login/"
    auth_data = {
        "username": username,
        "password": password
    }
    try:
        auth_response = requests.post(auth_url, json=auth_data)
        auth_response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"error: {e} while getting docker hub token")
        exit(1)

    docker_hub_token = auth_response.json()["token"]
    return docker_hub_token


def parse_image_digest(image_digest_json):
    if image_digest_json is None:
        return None
    try:
        images_infos = image_digest_json["images"]
        for images_info in images_infos:
            if images_info["architecture"] == "amd64":
                return images_info["digest"]
    except Exception as e:
        print(f"error: {e} while parsing image digest")
        exit(1)

    return None


def get_image_digest_json(image_name, tag, _token):
    registry_url = "https://hub.docker.com/v2/repositories/library/"
    image_url = registry_url + f"{image_name}/tags/{tag}"
    headers = {"Authorization": "Bearer " + _token}
    try:
        response = requests.get(image_url, headers=headers)
    except requests.exceptions.HTTPError as e:
        print(f"error: {e} while getting image digest json")
        exit(1)

    if response.status_code == 200:
        return response.json()
    else:
        return None


def get_package_urls(digest):
    data = copy.deepcopy(DSO_GET_PACKAGES_PAYLOAD)
    data["variables"]["digest"] = digest
    try:
        response = requests.post(DSO_GRAPH_API,
                                 headers={"accept": "application/json", "content-type": "application/json"},
                                 data=json.dumps(data))
    except requests.exceptions.HTTPError as e:
        print(f"error: {e} while getting package urls")
        exit(1)
    response_body = response.json()
    package_list = response_body["data"]["imagePackagesByDigest"]["imagePackages"]["packages"]
    _package_urls = list(map(lambda p: p["package"]["purl"], package_list))

    return _package_urls


def get_vuln_by_package_urls(_package_urls):
    data = copy.deepcopy(DSO_GET_VULN_PAYLOAD)
    data["variables"]["packageUrls"] = _package_urls
    try:
        response = requests.post(DSO_GRAPH_API,
                                 headers={"accept": "application/json", "content-type": "application/json"},
                                 data=json.dumps(data))
    except requests.exceptions.HTTPError as e:
        print(f"error: {e} while getting vuln by package urls")
        exit(1)
    return response.json()


def get_needed_vuln_by_response(response_json):
    cve_datas = []
    if response_json is None:
        return None
    if response_json["data"] is not None and response_json["data"]["vulnerabilitiesByPackage"] is not None:
        for item in response_json["data"]["vulnerabilitiesByPackage"]:
            if item["vulnerabilities"] is not None:
                for vuln in item["vulnerabilities"]:
                    needed_vuln = {"cveId": vuln["sourceId"], "cvss": vuln["cvss"]}
                    cve_datas.append(needed_vuln)
        return cve_datas


def get_needed_vuln_by_digest(digest):
    package_urls = get_package_urls(digest)
    response_json = get_vuln_by_package_urls(package_urls)
    return get_needed_vuln_by_response(response_json)


class DockerfileHandler:
    output_yaml_file_name = "dockerfile_handler_result.yaml"

    def __init__(self, microservices_name: str, force=False):
        current_dir = pathlib.Path(__file__).parent.resolve()
        self.microservices_name = microservices_name
        self.microservices_yaml_path = current_dir / f"../../microservices-yaml/{self.microservices_name}"
        self.microservices_dockerfiles = self.fetch_microservices_dockerfiles(self)
        self.result_yaml = current_dir / f"../../output/{self.microservices_name}/{self.output_yaml_file_name}"
        if force is not True and pathlib.Path(self.result_yaml).exists():
            with open(self.result_yaml, "r") as file:
                self.microservices_docker_cve_data = yaml.load(file, Loader=yaml.Loader)
        else:
            auth_info = read_config(pathlib.Path(__file__).parent.resolve() / "../../config.ini")
            self.token = get_docker_hub_token(auth_info["username"], auth_info["password"])
            self.microservices_docker_cve_data = self.generate_docker_cve_data(self)
            self.write_to_yaml_file(self)

    @staticmethod
    def fetch_microservices_dockerfiles(self) -> list:
        try:
            dockerfiles = list(self.microservices_yaml_path.rglob("Dockerfile"))
        except FileNotFoundError as e:
            print(f"error: {e} while getting dockerfiles")
            exit(1)

        return dockerfiles

    @staticmethod
    def generate_docker_cve_data(self) -> dict:
        docker_cve_data = {}
        for dockerfile in self.microservices_dockerfiles:
            docker_name = str(dockerfile.parent.name)
            with open(dockerfile, 'r') as f:
                dockerfile_content = f.read()

            dockerfile_items = dockerfile_content.split("\n")
            for dockerfile_item in dockerfile_items:
                if dockerfile_item.startswith("FROM"):
                    docker_cve_data[docker_name] = {}
                    base_image = dockerfile_item.split(" ")[1]
                    if len(base_image.split("/")) > 1:
                        base_image = base_image.split("/")[-1]
                    image_name = base_image.split(":")[0]
                    tag = base_image.split(":")[1]

                    docker_cve_data[docker_name]["baseImageName"] = image_name
                    docker_cve_data[docker_name]["tag"] = tag
                    try:
                        image_digest_json = get_image_digest_json(image_name, tag, self.token)
                    except Exception as e:
                        print(f"error: {e} while getting digest of dockerfile:", dockerfile)
                        exit(1)

                    if image_digest_json is not None:
                        digest_data = parse_image_digest(image_digest_json)
                        docker_cve_data[docker_name]["digest"] = digest_data
                        try:
                            docker_cve_data[docker_name]["vulnerabilities"] = get_needed_vuln_by_digest(digest_data)
                        except Exception as e:
                            print(f"error: {e} while getting cve data of dockerfile:", dockerfile)
                            exit(1)

        return docker_cve_data

    @staticmethod
    def write_to_yaml_file(self):
        if self.microservices_docker_cve_data is not None:
            with open(self.result_yaml, "w") as file:
                yaml.dump(self.microservices_docker_cve_data, file, default_flow_style=False)

    def get_image_info_by_image_name(self, image_name: str):
        for item in self.microservices_docker_cve_data:
            if str(item) in image_name:
                return self.microservices_docker_cve_data[item]

        return None
