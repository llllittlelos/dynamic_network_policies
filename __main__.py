import pathlib
from cilium_client import CiliumClient
from microservices_yaml_handler import MicroservicesYamlHandler

microservices = ("bookinfo", "online boutique", "sock shop")


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


if __name__ == '__main__':
    microservice_name: str = microservices[0]
    check_create_directory(microservice_name)

    # cilium_client = CiliumClient()
    # print("Hosts:", cilium_client.get_hosts())
    #
    # endpoints_json = cilium_client.get_endpoints_raw_json()
    # print("Endpoints:", endpoints_json)
    #
    # services_json = cilium_client.get_services_raw_json()
    # print("Services:", services_json)

    microservices_yaml_handler = MicroservicesYamlHandler(microservice_name)

    microservices_yaml_handler.enrich_containers()
    microservices_yaml_handler.enrich_services()
    microservices_yaml_handler.enrich_pod()

    print(len(microservices_yaml_handler.microservices_yaml_contents))
    print(microservices_yaml_handler.get_all_kinds())
