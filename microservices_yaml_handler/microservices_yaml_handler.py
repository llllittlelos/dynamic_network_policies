# microservices_yaml_handler/microservices_yaml_handler.py

import pathlib
import yaml


class MicroservicesYamlHandler:
    microservices_yaml_contents = []
    def __init__(self, microservices_name: str):
        self.microservices_name = microservices_name
        self.microservices_yaml_path = (pathlib.Path(__file__).parent.resolve()
                                        / f"../microservices-yaml/{self.microservices_name}")
        self.microservices_yaml_files = self.get_microservices_yaml_files(self)

    @staticmethod
    def get_microservices_yaml_files(self) -> list:
        yaml_files = list(self.microservices_yaml_path.rglob("*.yaml"))
        yml_files = list(self.microservices_yaml_path.rglob("*.yml"))
        yaml_files.extend(yml_files)

        return yaml_files

    def read_yaml_files(self) -> list:
        yaml_contents = []
        yaml_files = self.microservices_yaml_files
        for yaml_file in yaml_files:
            with open(yaml_file, "r") as file:
                try:
                    yaml_content = yaml.load_all(file, Loader=yaml.Loader)
                    yaml_contents.append(list(yaml_content))
                except yaml.YAMLError as e:
                    print(f"error: {e} while reading YAML file:", yaml_file)

        return yaml_contents

    def get_all_kinds(self) -> list:
        kinds = set()
        for yaml_content in self.read_yaml_files():
            for yaml_doc in yaml_content:
                if yaml_doc is not None and "kind" in yaml_doc:
                    kinds.add(yaml_doc["kind"])

        return list(kinds)
