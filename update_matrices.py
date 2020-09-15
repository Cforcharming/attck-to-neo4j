from cti_objs.mitre_objs import Matrix
from py2neo import Graph

graph = Graph(
    "http://localhost:7474",
    username="neo4j",
    password="attck"
)


def merge_matrix(name, mitre_id):
    matrix = Matrix(obj_dict=None)
    matrix.name = name
    matrix.mitre_id = mitre_id
    matrix.store(graph, None)


if __name__ == '__main__':
    merge_matrix('pre', 'MT0001')
    merge_matrix('enterprise', 'MT0002')
