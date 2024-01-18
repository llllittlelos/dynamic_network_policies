# microservices_yaml_handler/dockerfile_handler/dockerfile_handler.py

import pathlib
import requests
from configparser import ConfigParser


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


def get_image_vuln_by_digest(image_name, digest):
    database_url = "https://dso.docker.com/images/"
    image_url = database_url + f"{image_name}/digest/{digest}"
    try:
        response = requests.get(image_url)
    except requests.exceptions.HTTPError as e:
        print(f"error: {e} while getting image vuln by digest")
        exit(1)

    if response.status_code == 200:
        return response.content
    else:
        return None


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


auth_info = read_config(pathlib.Path(__file__).parent.resolve() / "../../config.ini")
token = get_docker_hub_token(auth_info["username"], auth_info["password"])


class DockerfileHandler:
    def __init__(self, microservices_name: str):
        self.microservices_name = microservices_name
        self.microservices_yaml_path = (pathlib.Path(__file__).parent.resolve()
                                        / f"../../microservices-yaml/{self.microservices_name}")
        self.microservices_dockerfiles = self.fetch_microservices_dockerfiles(self)
        self.microservices_docker_cve_data = self.generate_docker_cve_data(self)

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
            try:
                dockerfile_items = dockerfile_content.split("\n")
                for dockerfile_item in dockerfile_items:
                    if dockerfile_item.startswith("FROM"):
                        docker_cve_data[docker_name] = {}
                        base_image = dockerfile_item.split(" ")[1]
                        if len(base_image.split("/")) > 1:
                            base_image = base_image.split("/")[-1]
                        image_name = base_image.split(":")[0]
                        tag = base_image.split(":")[1]

                        docker_cve_data[docker_name]["image name"] = image_name
                        docker_cve_data[docker_name]["tag"] = tag

                        image_digest_json = get_image_digest_json(image_name, tag, token)

                        if image_digest_json is not None:
                            docker_cve_data[docker_name]["digest"] = parse_image_digest(image_digest_json)
                            # print(get_image_vuln_by_digest(image_name, docker_cve_data[docker_name]["digest"]))

            except Exception as e:
                print(f"error: {e} while reading dockerfile:", dockerfile)
                exit(1)

        return docker_cve_data


if __name__ == '__main__':
    print(get_image_vuln_by_digest("mysql", "sha256:f90d1aeb92a5c7b3a4178a3052d8bc27b1f52a811aacb27b619c10b778b9f281"))
    # microservices = ("bookinfo", "online boutique", "sock shop")
    # microservice_name: str = microservices[0]
    # dockerfile_handler = DockerfileHandler(microservice_name)
    # print(dockerfile_handler.microservices_docker_cve_data)
