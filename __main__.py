import pathlib
import shutil
import yaml

from cilium_client import CiliumClient
from microservices_yaml_handler import MicroservicesYamlHandler
from microservices_topology import MicroservicesTopology
from utils import utils

microservices = ("bookinfo", "online boutique", "sock shop")
# 不同微服务的YAML文件的排除项，即不需要进行处理的YAML文件
exclusions = {"bookinfo": ["bookinfo-psa.yaml", "bookinfo-dualstack.yaml"]}


def check_create_directory(_microservice_name):
    current_directory = pathlib.Path(__file__).parent.resolve()
    output_directory = current_directory / "output"
    microservice_output_directory = output_directory / _microservice_name
    cilium_client_directory = microservice_output_directory / "cilium_client"

    if not output_directory.exists():
        try:
            output_directory.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"error creating output directory: {e}")

    if not microservice_output_directory.exists():
        try:
            microservice_output_directory.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"error creating microservice output directory: {e}")

    if not cilium_client_directory.exists():
        try:
            cilium_client_directory.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"error creating cilium_client directory: {e}")


def output_for_test(test_microservices_yaml_handler, test_cilium_client, remove_test_output=False):
    current_directory = pathlib.Path(__file__).parent.resolve()
    output_directory = current_directory / "output"
    test_directory = output_directory / test_microservices_yaml_handler.microservices_name / "test"

    if remove_test_output:
        try:
            # 递归删除目录及其内容
            shutil.rmtree(test_directory)
            print(f"directory {test_directory} removed successfully.")
        except OSError as e:
            print(f"error: {e}")

        return

    if not test_directory.exists():
        try:
            test_directory.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"error creating output directory: {e}")

    with open(test_directory / "yaml_result.yaml", "w") as file:
        yaml.dump(test_microservices_yaml_handler.microservices_yaml_contents, file, default_flow_style=False)
    with open(test_directory / "services_result.yaml", "w") as file:
        yaml.dump(test_cilium_client.get_service_items_by_namespace(microservice_namespace),
                  file, default_flow_style=False)
    with open(test_directory / "endpoints_result.yaml", "w") as file:
        yaml.dump(test_cilium_client.get_endpoint_items_by_namespace(microservice_namespace),
                  file, default_flow_style=False)


if __name__ == '__main__':
    force = False
    pic_output = False
    html_output = False
    test_yaml_output = False

    microservice_name: str = microservices[0]
    microservice_namespace = microservice_name
    check_create_directory(microservice_name)

    cilium_client = CiliumClient(microservice_name, force)

    microservices_yaml_handler = MicroservicesYamlHandler(microservice_name, exclusions[microservice_name], force)
    microservices_yaml_handler.enrich_containers()
    microservices_yaml_handler.enrich_services()
    microservices_yaml_handler.enrich_pod()
    microservices_yaml_handler.calculate_global_score()

    raw_services_inner_ip_list = []
    for service_item in cilium_client.get_service_items_by_namespace(microservice_namespace):
        backend_address_set = set()
        for backend_address in service_item["spec"]["backend-addresses"]:
            backend_address_set.add(backend_address["ip"])
        raw_services_inner_ip_list.append(backend_address_set)

    frozen_sets = [frozenset(s) for s in raw_services_inner_ip_list]
    unique_sets = set(frozen_sets)
    services_inner_ip_list = [set(s) for s in unique_sets]

    # 表示的包含了大于1个IP的服务，即有多个后端IP的服务
    services_inner_ip_list = [s for s in services_inner_ip_list if len(s) > 1]

    data_for_graph = {}
    # endpoint可以视作pod的接口实现，所以直接遍历endpoint即可
    endpoint_items = cilium_client.get_endpoint_items_by_namespace(microservice_namespace)
    for endpoint_item in endpoint_items:
        pod_name = endpoint_item["status"]["external-identifiers"]["k8s-pod-name"]
        data_for_graph[pod_name] = {}
        container_info_list = microservices_yaml_handler.get_container_info_by_pod_name(pod_name)
        pod_container_image_name_set = set()
        for container_info in container_info_list:
            for item in container_info:
                if "image" in item:
                    pod_container_image_name_set.add(item["image"])
        pod_container_image_name_list = list(pod_container_image_name_set)
        data_for_graph[pod_name]["innerIp"] = endpoint_item["status"]["networking"]["addressing"][0]["ipv4"]
        data_for_graph[pod_name][utils.score_types.global_score] \
            = microservices_yaml_handler.get_pod_score(pod_name, utils.score_types.global_score)
        data_for_graph[pod_name][utils.score_types.access_score] \
            = microservices_yaml_handler.get_pod_score(pod_name, utils.score_types.access_score)
        data_for_graph[pod_name]["containers"] = pod_container_image_name_list
        data_for_graph[pod_name]["containerInfos"] = container_info_list
        data_for_graph[pod_name]["endpointInfos"] = endpoint_item

    microservices_topology = MicroservicesTopology(microservice_name, data_for_graph, services_inner_ip_list)

    microservices_topology.generate_graph_from_data()

    # node是图论定义的节点，不是K8S的概念
    # 这个方法必须执行，因为涉及到边的权重的计算
    initial_node, paths = microservices_topology.get_initial_node_and_shortest_path()

    if pic_output:
        microservices_topology.generate_simple_picture()
    if html_output:
        microservices_topology.draw_graph_with_pyecharts()
    # 保存原始输出信息以供调试，第三个参数为True表示删除原有的测试输出
    if test_yaml_output:
        output_for_test(microservices_yaml_handler, cilium_client, False)
