# network_policies_generator/network_policies_generator.py
import copy
import pathlib
import yaml

cilium_network_policy_template = {
    "apiVersion": "cilium.io/v2",
    "kind": "CiliumNetworkPolicy",
    "metadata": {
        "name": "",
        "namespace": ""
    },
    "spec": {
        "endpointSelector": {
            "matchLabels": {
                "app": "",
                "version": ""
            }
        },
        "ingress": [],
        "egress": []
    }
}


class NetworkPoliciesGenerator:
    l3_l4_network_policies = []
    l7_network_policies = []

    def __init__(self, microservices_name, raw_data):
        self.microservices_name = microservices_name
        current_dir = pathlib.Path(__file__).parent.resolve()
        self.network_policies_path = current_dir / f"../output/{self.microservices_name}/network_policies/"

        for key in raw_data:
            cilium_network_policy: dict[str, any] = copy.deepcopy(cilium_network_policy_template)
            endpoint_info = raw_data[key]["endpointInfos"]

            labels_dict = {}
            for label_str in endpoint_info["status"]["identity"]["labels"]:
                labels_dict.update(self.parse_label_str(label_str))

            cilium_network_policy["metadata"]["name"] = (labels_dict["app"] + "-" + labels_dict["version"]
                                                         + "-l3-l4-policy")
            cilium_network_policy["metadata"]["namespace"] = (
                endpoint_info["status"]["external-identifiers"]["k8s-namespace"])
            cilium_network_policy["spec"]["endpointSelector"]["matchLabels"]["app"] = labels_dict["app"]
            cilium_network_policy["spec"]["endpointSelector"]["matchLabels"]["version"] = labels_dict["version"]

            self.l3_l4_network_policies.append(cilium_network_policy)

    @staticmethod
    def parse_label_str(label_str: str) -> dict:
        label_str = label_str.strip()
        label_info = label_str.split(":")[-1]
        return {label_info.split("=")[0]: label_info.split("=")[1]}

    def write_policies_to_yaml_file(self):
        for l3_l4_network_policy in self.l3_l4_network_policies:
            filename = (self.network_policies_path / (l3_l4_network_policy["metadata"]["name"] + ".yaml"))
            with open(filename, "w") as file:
                yaml.dump(l3_l4_network_policy, file, default_flow_style=False, sort_keys=False)
