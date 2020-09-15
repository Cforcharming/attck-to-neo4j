from py2neo import Node, Relationship


class SDO:
    """
    Defines the abstract class of all SDO objects in ATT&CK.
    Each SDO (technique, tactic, software, etc) can inherit from this class.
    Since these objects have some common properties.
    """
    
    def __init__(self, sdo_type, obj_dict, used_by=None, relation='is used by', relation_inv='uses'):
        
        if obj_dict is not None:
            
            self._mitre_id = None
            try:
                external_references = obj_dict['external_references']
                for reference in external_references:
                    if reference['source_name'] == 'mitre-attack':
                        self._mitre_id = reference['external_id']
                        break
            except KeyError:
                self._mitre_id = None
            
            try:
                self._name = obj_dict['name']
            except KeyError:
                self._name = None
            try:
                self._description = obj_dict['description']
            except KeyError:
                self._description = None
            try:
                self._deprecated = obj_dict['deprecated']
            except KeyError:
                self._deprecated = None
            try:
                self._revoked = obj_dict['revoked']
            except KeyError:
                self._revoked = None
            try:
                self._old_id = obj_dict['old_id']
            except KeyError:
                self._old_id = None
        else:
            self._mitre_id = None
            self._name = None
            self._description = None
            self._deprecated = None
            self._revoked = None
            self._old_id = None
        
        self._used_by = used_by
        self._relation = relation
        self._relation_inv = relation_inv
        self._type = sdo_type
    
    def store(self, graph, node):
        print('INSERT SDO', self._type, 'Name:', self._name)
        my_node = Node(
                self._type,
                name=self._name,
                mitre_id=self._mitre_id,
                description=self._description,
                deprecated=self._deprecated,
                revoked=self._revoked,
                old_id=self._old_id
            )
        graph.merge(my_node, self._type, 'name')
        self.create_sro().store(graph, my_node, node)
        return my_node
    
    @property
    def used_by(self):
        return self._used_by
    
    @used_by.setter
    def used_by(self, used_by):
        self._used_by = used_by
    
    def create_sro(self):
        return SRO(self, self._relation, self._relation_inv, self._used_by)
    
    @property
    def mitre_id(self):
        return self._mitre_id
    
    @mitre_id.setter
    def mitre_id(self, mitre_id):
        self._mitre_id = mitre_id
    
    @property
    def name(self):
        return self._name
    
    @name.setter
    def name(self, name):
        self._name = name
    
    @property
    def description(self):
        return self._description
    
    @description.setter
    def description(self, description):
        self._description = description
    
    @property
    def deprecated(self):
        return self._deprecated
    
    @deprecated.setter
    def deprecated(self, deprecated):
        self._deprecated = deprecated
    
    @property
    def revoked(self):
        return self._revoked
    
    @revoked.setter
    def revoked(self, revoked):
        self._revoked = revoked
    
    @property
    def old_id(self):
        return self._old_id
    
    @old_id.setter
    def old_id(self, old_id):
        self._old_id = old_id
    
    @property
    def type(self):
        return self._type
    
    @type.setter
    def type(self, sdo_type):
        self._type = sdo_type


class SRO:
    """
    Defines the relationships between two SDOs.
    The relationship is actually a pair of SDOs
    Two relationships are equal if in the id of the SDOs are the same
    """
    
    def __init__(self, sdo1: SDO, relation, relation_inv, sdo2: SDO):
        
        self._sdo1 = sdo1
        self._sdo2 = sdo2
        self._relation = relation
        self._relation_inv = relation_inv
    
    @property
    def sdo1(self):
        return self._sdo1
    
    @sdo1.setter
    def sdo1(self, sdo1):
        self._sdo1 = sdo1
    
    @property
    def sdo2(self):
        return self._sdo2
    
    @sdo2.setter
    def sdo2(self, sdo2):
        self._sdo2 = sdo2
    
    def store(self, graph, n1, n2):
        if self._sdo2 is not None:
            print('INSERT SRO', self._sdo1.name, self._relation, self._sdo2.name)
            r1 = Relationship.type(self._relation)
            r2 = Relationship.type(self._relation_inv)
            s = r1(n1, n2) | r2(n2, n1)
            graph.merge(s)
    
    def __eq__(self, other):
        if self._sdo1.name == other.sdo1.name and self._sdo2.name == other.sdo2.name:
            return True
        elif self._sdo1.name == other.sdo2.name and self._sdo2.name == other.sdo1.name:
            return True
        else:
            return False
