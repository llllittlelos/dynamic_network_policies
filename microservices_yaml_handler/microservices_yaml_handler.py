# microservices_yaml_handler/microservices_yaml_handler.py

import pathlib
import yaml
from collections import namedtuple
from microservices_yaml_handler.dockerfile_handler import DockerfileHandler


class MicroservicesYamlHandler:
    # TODO: 这只是常规安全检查，L7的网络策略需要获取HTTP有关的配置文件
    needed_yaml_kind = ("Pod", "Deployment", "DaemonSet", "ReplicaSet", "Namespace", "Service", "ServiceAccount",
                        "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "Secret", "PersistentVolume",
                        "Ingress")
    needed_yaml_spec = ("containers", "initContainers", "volumes", "volumeMounts", "persistentVolumeClaim")
    ScoreTypes = namedtuple("ScoreTypes",
                            ["global_score", "container_score", "security_context_score",
                             "access_score", "pod_score", "volume_score"])
    score_types = ScoreTypes(global_score="globalScore", container_score="containerScore",
                             security_context_score="securityContextScore", access_score="accessScore",
                             pod_score="podScore", volume_score="volumeScore")

    def __init__(self, microservices_name: str, force=False):
        self.microservices_name = microservices_name
        self.microservices_yaml_path = (pathlib.Path(__file__).parent.resolve()
                                        / f"../microservices-yaml/{self.microservices_name}")
        self.microservices_yaml_files = self.fetch_microservices_yaml_files(self)
        # microservices_yaml_contents是过滤后的，仅包括需要的yaml文件的内容
        self.microservices_yaml_contents = self.read_needed_yaml_files(self)
        self.dockerfile_handler = DockerfileHandler(microservices_name, force)

    @staticmethod
    def fetch_microservices_yaml_files(self) -> list:
        try:
            yaml_files = list(self.microservices_yaml_path.rglob("*.yaml"))
            yml_files = list(self.microservices_yaml_path.rglob("*.yml"))
        except FileNotFoundError as e:
            print(f"error: {e} while getting microservices YAML files")
            exit(1)
        yaml_files.extend(yml_files)

        return yaml_files

    @staticmethod
    def __filter_yaml_content(self, yaml_content) -> list:
        needed_yaml_content = []
        for yaml_item in yaml_content:
            if yaml_item is not None and "kind" in yaml_item and yaml_item["kind"] in self.needed_yaml_kind:
                for item in self.score_types:
                    yaml_item[item] = 0
                needed_yaml_content.append(yaml_item)

            elif yaml_item is not None and "spec" in yaml_item:
                queue = []
                if yaml_item["spec"] is not None:
                    queue.append(yaml_item["spec"])
                while len(queue) > 0:
                    spec = queue.pop(0)
                    if spec is None:
                        continue
                    for spec_item in spec:
                        if spec_item in self.needed_yaml_spec:
                            for item in self.score_types:
                                yaml_item[item] = 0
                            needed_yaml_content.append(yaml_item)
                        elif "spec" in spec and spec["spec"] is not None:
                            queue.append(spec["spec"])
                        elif "template" in spec and spec["template"] is not None:
                            queue.append(spec["template"])

        return needed_yaml_content

    @staticmethod
    def read_needed_yaml_files(self) -> list:
        yaml_contents = []
        yaml_files = self.microservices_yaml_files
        for yaml_file in yaml_files:
            with open(yaml_file, "r") as file:
                try:
                    yaml_content = yaml.load_all(file, Loader=yaml.Loader)
                except yaml.YAMLError as e:
                    print(f"error: {e} while reading YAML file:", yaml_file)
                    exit(1)

                filtered_yaml_content = self.__filter_yaml_content(self, list(yaml_content))
                if len(filtered_yaml_content) > 0:
                    yaml_contents.extend(filtered_yaml_content)

        return yaml_contents

    def enrich_containers(self):
        for yaml_item in self.microservices_yaml_contents:
            if yaml_item is None:
                continue
            if "spec" not in yaml_item:
                continue
            if "template" not in yaml_item["spec"]:
                continue
            if "spec" not in yaml_item["spec"]["template"]:
                continue
            for spec_item in yaml_item["spec"]["template"]["spec"]:
                if spec_item == "containers" or spec_item == "initContainers":
                    for container_item in yaml_item["spec"]["template"]["spec"][spec_item]:
                        if "image" in container_item:
                            image = container_item["image"]
                            image_search_name = image.split("/")[-1]
                            image_info = (self.dockerfile_handler.
                                          get_image_info_by_image_name(image_search_name))
                            if image_info is not None:
                                container_item["imageInfo"] = image_info
                                yaml_item[self.score_types.container_score] = len(image_info["vulnerabilities"])
                        if "securityContext" in container_item:
                            security_context = container_item["securityContext"]
                            security_context_score = 0
                            if "capabilities" in security_context:
                                capabilities = security_context["capabilities"]
                                capabilities_score = 0
                                for item in capabilities:
                                    capabilities_score += 5 * len(capabilities[item])
                                security_context_score += capabilities_score

                            if "runAsNonRoot" in security_context:
                                if not security_context["runAsNonRoot"]:
                                    security_context_score += 100
                            else:
                                security_context_score += 100

                            if "allowPrivilegeEscalation" in security_context:
                                if security_context["allowPrivilegeEscalation"]:
                                    security_context_score += 100

                            if "privileged" in security_context:
                                if security_context["privileged"]:
                                    security_context_score += 100

                            if "readOnlyRootFilesystem" in security_context:
                                if not security_context["readOnlyRootFilesystem"]:
                                    security_context_score += 100
                            else:
                                security_context_score += 100

                            yaml_item[self.score_types.security_context_score] = security_context_score

                        if "volumeMounts" in container_item:
                            volume_mounts = container_item["volumeMounts"]
                            yaml_item[self.score_types.volume_score] = 10 * len(volume_mounts)

    def enrich_services(self):
        accessibility_rules = ("ClusterIP", "NodePort", "LoadBalancer", "ExternalName")
        accessibility_kind = "Ingress"
        for yaml_item in self.microservices_yaml_contents:
            if yaml_item["kind"] == accessibility_kind:
                yaml_item[self.score_types.access_score] = 100
                continue
            if yaml_item is None:
                continue
            if "spec" not in yaml_item:
                continue
            if "type" not in yaml_item["spec"]:
                continue
            if yaml_item["spec"]["type"] in accessibility_rules:
                yaml_item[self.score_types.access_score] = 100
                continue

    def enrich_pod(self):
        pod_rules = ("hostPID", "hostNetwork")
        affinity_rules = ("nodeAffinity", "podAffinity")
        for yaml_item in self.microservices_yaml_contents:
            if yaml_item["kind"] != "Pod":
                continue
            if "spec" in yaml_item and yaml_item["spec"] is not None:
                pod_score = 0
                for pod_rule in pod_rules:
                    if pod_rule in yaml_item["spec"]:
                        if yaml_item["spec"][pod_rule]:
                            pod_score += 100

                for affinity_rule in affinity_rules:
                    if affinity_rule in yaml_item["spec"]:
                        if yaml_item["spec"][affinity_rule]:
                            pod_score += 0.4

                yaml_item[self.score_types.pod_score] = pod_score

    def get_all_kinds(self) -> list:
        kinds = set()
        for yaml_item in self.microservices_yaml_contents:
            if yaml_item is not None and "kind" in yaml_item:
                kinds.add(yaml_item["kind"])

        return list(kinds)
