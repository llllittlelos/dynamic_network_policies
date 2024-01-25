# microservices_yaml_handler/microservices_yaml_handler.py

import pathlib
import yaml
from microservices_yaml_handler.dockerfile_handler import DockerfileHandler
from utils import utils


class MicroservicesYamlHandler:
    # TODO: 这只是常规安全检查，L7的网络策略需要获取HTTP有关的配置文件，个人感觉这里也获取了一部分的HTTP有关的配置文件
    needed_yaml_kind = ("Pod", "Deployment", "DaemonSet", "ReplicaSet", "Namespace", "Service", "ServiceAccount",
                        "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "Secret", "PersistentVolume",
                        "Ingress")
    needed_yaml_spec = ("containers", "initContainers", "volumes", "volumeMounts", "persistentVolumeClaim")
    score_types = utils.score_types
    accessible_item = []

    def __init__(self, microservices_name: str, exclusions_list: list, force=False):
        self.microservices_name = microservices_name
        self.exclusions_list = exclusions_list
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
            if str(yaml_file).split("\\")[-1] in self.exclusions_list:
                continue
            with open(yaml_file, "r") as file:
                try:
                    yaml_content = yaml.load_all(file, Loader=yaml.Loader)
                except yaml.YAMLError as e:
                    print(f"error: {e} while reading YAML file:", yaml_file)
                    exit(1)

                filtered_yaml_content = self.__filter_yaml_content(self, list(yaml_content))
                if len(filtered_yaml_content) > 0:
                    for item in filtered_yaml_content:
                        if item not in yaml_contents:
                            yaml_contents.append(item)

        return yaml_contents

    def enrich_containers(self):
        for yaml_content in self.microservices_yaml_contents:
            if yaml_content is None:
                continue
            if "spec" not in yaml_content:
                continue
            if "template" not in yaml_content["spec"]:
                continue
            if "spec" not in yaml_content["spec"]["template"]:
                continue
            for spec_item in yaml_content["spec"]["template"]["spec"]:
                if spec_item == "containers" or spec_item == "initContainers":
                    for container_item in yaml_content["spec"]["template"]["spec"][spec_item]:
                        if "image" in container_item:
                            image = container_item["image"]
                            image_search_name = image.split("/")[-1]
                            image_info = (self.dockerfile_handler.
                                          get_image_info_by_image_name(image_search_name))
                            if image_info is not None:
                                container_item["imageInfo"] = image_info
                                yaml_content[self.score_types.container_score] = len(image_info["vulnerabilities"])
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

                            yaml_content[self.score_types.security_context_score] = security_context_score

                        if "volumeMounts" in container_item:
                            volume_mounts = container_item["volumeMounts"]
                            yaml_content[self.score_types.volume_score] = 10 * len(volume_mounts)

    def enrich_services(self):
        accessibility_rules = ("ClusterIP", "NodePort", "LoadBalancer", "ExternalName")
        accessibility_kind = "Ingress"
        for yaml_content in self.microservices_yaml_contents:
            if yaml_content["kind"] == accessibility_kind:
                yaml_content[self.score_types.access_score] = 100
                self.accessible_item.append(yaml_content)
                continue
            if yaml_content is None:
                continue
            if "spec" not in yaml_content:
                continue
            if "type" not in yaml_content["spec"]:
                continue
            if yaml_content["spec"]["type"] in accessibility_rules:
                yaml_content[self.score_types.access_score] = 100
                self.accessible_item.append(yaml_content)
                continue

    def enrich_pod(self):
        pod_rules = ("hostPID", "hostNetwork")
        affinity_rules = ("nodeAffinity", "podAffinity")
        for yaml_content in self.microservices_yaml_contents:
            if yaml_content["kind"] != "Pod":
                continue
            if "spec" in yaml_content and yaml_content["spec"] is not None:
                pod_score = 0
                for pod_rule in pod_rules:
                    if pod_rule in yaml_content["spec"]:
                        if yaml_content["spec"][pod_rule]:
                            pod_score += 100

                for affinity_rule in affinity_rules:
                    if affinity_rule in yaml_content["spec"]:
                        if yaml_content["spec"][affinity_rule]:
                            pod_score += 0.4

                yaml_content[self.score_types.pod_score] = pod_score

    def calculate_global_score(self):
        for yaml_content in self.microservices_yaml_contents:
            if yaml_content is None:
                continue
            global_score = 0
            for item in self.score_types:
                global_score += yaml_content[item]
            yaml_content[self.score_types.global_score] = global_score

    def get_all_kinds(self) -> list:
        kinds = set()
        for yaml_content in self.microservices_yaml_contents:
            if yaml_content is not None and "kind" in yaml_content:
                kinds.add(yaml_content["kind"])

        return list(kinds)

    def get_all_pods_names(self) -> list:
        pods_names = set()
        for yaml_content in self.microservices_yaml_contents:
            if yaml_content is not None and "kind" in yaml_content and yaml_content["kind"] == "Deployment":
                pods_names.add(yaml_content["metadata"]["name"])

        return list(pods_names)

    def get_all_containers_names(self) -> list:
        containers_names = set()
        for yaml_content in self.microservices_yaml_contents:
            if yaml_content is None:
                continue
            if "spec" not in yaml_content:
                continue
            if "template" not in yaml_content["spec"]:
                continue
            if "spec" not in yaml_content["spec"]["template"]:
                continue
            for spec_item in yaml_content["spec"]["template"]["spec"]:
                if spec_item == "containers" or spec_item == "initContainers":
                    for container_item in yaml_content["spec"]["template"]["spec"][spec_item]:
                        if "image" in container_item:
                            containers_names.add(container_item["image"])

        return list(containers_names)

    def get_container_info_by_pod_name(self, pod_name: str):
        container_infos = []
        for yaml_content in self.microservices_yaml_contents:
            if yaml_content is None:
                continue
            if yaml_content["kind"] != "Deployment":
                continue
            if "spec" not in yaml_content:
                continue
            if "template" not in yaml_content["spec"]:
                continue
            if "spec" not in yaml_content["spec"]["template"]:
                continue
            if "containers" in yaml_content["spec"]["template"]["spec"]:
                if yaml_content["metadata"]["name"] in pod_name:
                    container_infos.append(yaml_content["spec"]["template"]["spec"]["containers"])
            if "initContainers" in yaml_content["spec"]["template"]["spec"]:
                if yaml_content["metadata"]["name"] in pod_name:
                    container_infos.append(yaml_content["spec"]["template"]["spec"]["initContainers"])

        return container_infos

    def get_accessible_item_name_list(self) -> list:
        accessible_item_name_set = set()
        for item in self.accessible_item:
            if item["kind"] == "Service":
                accessible_item_name_set.add(item["metadata"]["labels"]["app"])

        return list(accessible_item_name_set)

    def get_pod_score(self, pod_name: str, score_type: str) -> int:
        score = -1
        for yaml_content in self.microservices_yaml_contents:
            if yaml_content is None:
                continue
            if yaml_content["kind"] != "Deployment":
                continue
            if "spec" not in yaml_content:
                continue
            if "template" not in yaml_content["spec"]:
                continue
            if "spec" not in yaml_content["spec"]["template"]:
                continue
            if yaml_content["metadata"]["name"] in pod_name:
                if score_type == utils.score_types.access_score:
                    accessible_item_name = self.get_accessible_item_name_list()
                    for item in accessible_item_name:
                        if item in pod_name:
                            if yaml_content[score_type] < 100:
                                yaml_content[score_type] = 100
                if yaml_content[score_type] > score:
                    score = yaml_content[score_type]

        return score
