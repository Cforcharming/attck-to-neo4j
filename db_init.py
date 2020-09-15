from stix2 import FileSystemSource
from cti_utils import *
from cti_objs.mitre_objs import *
from py2neo import Graph
from time import time

graph = Graph(
    "http://localhost:7474",
    username="neo4j",
    password="attck"
)


def from_matrix_to_graph(matrix_path):
    
    # initialise the matrix
    fs = FileSystemSource(matrix_path)
    matrix = Matrix(obj_dict=None)
    matrix.name = matrix_path.split('/')[2].split('-')[0]
    m_node = matrix.store(graph, None)
    
    # get and store all software of a matrix
    groups = get_all_groups(fs)
    for g in groups:
        g_obj = Group(obj_dict=g, used_by=None)
        g_node = g_obj.store(graph, None)
        software = get_software_by_groups(fs, g['id'])
        for s in software:
            s_obj = Software(obj_dict=s, used_by=Group(obj_dict=g, used_by=None))
            s_obj.store(graph, g_node)

    # get and store all tactics of a matrix
    tactics = list(get_tactics_by_matrix(fs).values())[0]
    for tactic in tactics:
        tact = Tactic(obj_dict=tactic, used_by=matrix)
        ta_node = tact.store(graph, m_node)

        # get and store all techniques of a tactic
        techniques = get_tactic_techniques(fs, tactic['name'].lower().replace(' ', '-'))
        for technique in techniques:
            tech = Technique(obj_dict=technique, used_by=tact)
            te_node = tech.store(graph, ta_node)

            # get and store all related software, groups and mitigations of a technique
            soft, group, mitigation = get_software_group_mitigations(fs, technique['id'])

            for s in soft:
                s_obj = Software(obj_dict=s, used_by=tech)
                s_obj.store(graph, te_node)

            for g in group:
                g_obj = Group(obj_dict=g, used_by=tech)
                g_obj.store(graph, te_node)

            for m in mitigation:
                m_obj = Mitigation(obj_dict=m, used_by=tech)
                m_obj.store(graph, te_node)


if __name__ == '__main__':
    
    t1 = time()
    from_matrix_to_graph('./cti/enterprise-attack')
    from_matrix_to_graph('./cti/pre-attack')
    # from_matrix_to_graph('./cti/mobile-attack')
    print(time()-t1, 'seconds')
