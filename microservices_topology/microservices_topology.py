# microservices_topology/microservices_topology.py
import networkx as nx
import matplotlib.pyplot as plt
import pathlib

from utils import utils
from pyecharts import options as opts
from pyecharts.charts import Graph


class MicroservicesTopology:
    def __init__(self, microservice_name, data_for_graph: dict, services_inner_ip_list: list):
        self.microservice_name = microservice_name
        self.graph = nx.DiGraph()
        self.data_for_graph = data_for_graph
        self.services_inner_ip_list = services_inner_ip_list
        self.initial_node_shortest_paths = None
        current_directory = pathlib.Path(__file__).parent.resolve()
        self.graph_output_directory = current_directory / "../output" / microservice_name

    def add_pod(self, pod_name):
        self.graph.add_node(pod_name, type='pod')

    def add_container(self, pod_name, container_image_name):
        self.graph.add_node(container_image_name, type='container', parent_pod=pod_name)
        self.graph.add_edge(pod_name, container_image_name, weight=100)

    def add_pod_connection(self, pod1, pod2, weight):
        self.graph.add_edge(pod1, pod2, type='podConnection', weight=weight)

    def are_ips_in_same_service(self, ip1, ip2):
        for ip_set in self.services_inner_ip_list:
            if ip1 in ip_set and ip2 in ip_set:
                return True
        return False

    def generate_graph_from_data(self):
        for pod in self.data_for_graph:
            self.add_pod(pod)
            for container in self.data_for_graph[pod]["containers"]:
                self.add_container(pod, container)

        for pod1 in self.data_for_graph:
            for pod2 in self.data_for_graph:
                pod1_score = self.data_for_graph[pod1][utils.score_types.global_score]
                pod2_score = self.data_for_graph[pod2][utils.score_types.global_score]
                if self.are_ips_in_same_service(self.data_for_graph[pod1]["innerIp"],
                                                self.data_for_graph[pod2]["innerIp"]):
                    pod1_score += 100
                    pod2_score += 100
                if pod1 != pod2:
                    self.add_pod_connection(pod1, pod2, 1 / pod1_score)
                    self.add_pod_connection(pod2, pod1, 1 / pod2_score)

    def get_shortest_path_by_node(self, node):
        return nx.shortest_path(self.graph, source=node, weight='weight')

    def get_initial_node_and_shortest_path(self):
        for pod in self.data_for_graph:
            if self.data_for_graph[pod][utils.score_types.access_score] > 0:
                self.initial_node_shortest_paths = self.get_shortest_path_by_node(pod)
                return pod, self.initial_node_shortest_paths

    def generate_simple_picture(self):
        pos = nx.spring_layout(self.graph)
        nx.draw(self.graph, pos, with_labels=True, node_color='skyblue', edge_color='black', node_size=2000,
                font_size=10,
                font_weight='bold')
        # 添加边的标签
        edge_labels = nx.get_edge_attributes(self.graph, 'weight')
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels)

        plt.show()

    def draw_graph_with_pyecharts(self):
        nodes = [{"name": node, "symbolSize": 10} for node in self.graph.nodes()]
        links = []
        categories = [{"name": "Pod"}, {"name": "Container"}]

        # 获取最短路径上的边
        shortest_path_edges = set()
        if self.initial_node_shortest_paths:
            for path in self.initial_node_shortest_paths.values():
                for i in range(len(path) - 1):
                    shortest_path_edges.add((path[i], path[i + 1]))

        # 添加边，设置不同的样式
        for u, v in self.graph.edges():
            if (u, v) in shortest_path_edges or (v, u) in shortest_path_edges:
                links.append({"source": u, "target": v, "lineStyle": {"normal": {"color": "red", "width": 2}}})
            else:
                links.append({"source": u, "target": v})

        # 更新节点类型
        for node in nodes:
            node_type = self.graph.nodes[node["name"]]["type"]
            if node_type == "pod":
                node["category"] = 0
            else:  # container
                node["category"] = 1

        # 创建图表
        g = Graph(init_opts=opts.InitOpts(width="100%", height="800px"))
        g.add("", nodes, links, categories, repulsion=8000)

        # 保存为 HTML 文件
        g.render(self.graph_output_directory / (self.microservice_name + ".html"))
