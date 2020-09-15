from cti_objs.stix_abstract_object import SDO


class Matrix(SDO):
    
    def __init__(self, obj_dict):
        super().__init__(sdo_type='matrix', obj_dict=obj_dict)


class Tactic(SDO):
    
    def __init__(self, obj_dict, used_by):
        super().__init__(obj_dict=obj_dict, used_by=used_by, sdo_type='tactic', relation='in', relation_inv='contains')


class Technique(SDO):
    
    def __init__(self, obj_dict, used_by):
        
        super().__init__(sdo_type='technique', used_by=used_by, obj_dict=obj_dict)
        
        if obj_dict is not None:
            
            try:
                self._platform = obj_dict['x_mitre_platforms']
            except KeyError:
                self._platform = None

            try:
                self._permission = obj_dict['x_mitre_permissions_required']
            except KeyError:
                self._permission = None

            try:
                self._effective = obj_dict['x_mitre_effective_permissions']
            except KeyError:
                self._effective = None

            try:
                self._bypass = obj_dict['x_mitre_defense_bypassed']
            except KeyError:
                self._bypass = None

            try:
                self._requirements = obj_dict['x_mitre_system_requirements'][0]
            except KeyError:
                self._requirements = None
            
            try:
                self._network = obj_dict['x_mitre_network_requirements']
            except KeyError:
                self._network = False
            
            try:
                self._remote = obj_dict['x_mitre_remote_support']
            except KeyError:
                self._remote = False
    
    def store(self, graph, node):
        
        my_node = super().store(graph, node)
        my_node['requirements'] = self._requirements
        my_node['network'] = self._network
        my_node['remote'] = self._remote
        my_node['platform'] = self._platform
        my_node['permission_required'] = self._permission
        my_node['effective_permission'] = self._effective
        my_node['defense_bypassed'] = self._bypass
        graph.push(my_node)
        
        graph.merge(my_node, self._type, 'name')
        
        return my_node


class Software(SDO):
    
    def __init__(self, obj_dict, used_by):
        super().__init__(obj_dict=obj_dict, used_by=used_by, sdo_type='software')


class Group(SDO):
    
    def __init__(self, obj_dict, used_by):
        super().__init__(obj_dict=obj_dict, used_by=used_by, sdo_type='group', relation='in', relation_inv='contains')


class Mitigation(SDO):
    
    def __init__(self, obj_dict, used_by):
        super().__init__(obj_dict=obj_dict, used_by=used_by, sdo_type='mitigation')
