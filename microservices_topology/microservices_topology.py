# microservices_topology/microservices_topology.py
import networkx as nx
import matplotlib.pyplot as plt


class MicroservicesTopology:
    def __init__(self):
        self.graph = nx.Graph()

    def add_pod(self, pod_name):
        self.graph.add_node(pod_name, type='pod')

    def add_container(self, pod_name, container_image_name):
        self.graph.add_node(container_image_name, type='container', parent_pod=pod_name)
        self.graph.add_edge(pod_name, container_image_name)

    def add_pod_connection(self, pod1, pod2, weight):
        self.graph.add_edge(pod1, pod2, type='pod_connection', weight=1)

    def generate_picture(self):
        pos = nx.spring_layout(self.graph)
        nx.draw(self.graph, pos, with_labels=True, node_color='skyblue', edge_color='black', node_size=2000, font_size=10,
                font_weight='bold')

        plt.show()
