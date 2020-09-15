from stix2 import Filter
from stix2.utils import get_type_from_id
from itertools import chain

'''
All below functions are from https://github.com/mitre/cti/blob/master/USAGE.md

fs = stix2.FileSystemSource('./cti/enterprise-attack')
'''


def get_all_software(src):
    """
    Get All Software

    Since ATT&CK software can either be classified as a tool or malware in STIX,
    you must query for both of them in order to find all software.
    The library's query function does not have the capability to do logical OR,
    so two separate queries must be performed.
    The results are merged together into one list.

    get_all_software(fs)
    """
    filts = [
        [Filter('type', '=', 'malware')],
        [Filter('type', '=', 'tool')]
    ]
    return list(chain.from_iterable(
        src.query(f) for f in filts
    ))


def get_all_groups(src):
    """
    Get All Groups
    
    get_all_groups(fs)
    """
    filts = Filter('type', '=', 'intrusion-set')
    return src.query(filts)


'''
Get Techniques by name or content

get_technique_by_name(fs, 'Rundll32')
get_techniques_by_content(fs, 'rundll32.exe')

Here we query the same technique in two different ways. 
In addition to the Rundll32 technique, notice that the latter method results in a second technique 
(Masquerading) because it also contains the term "rundll32.exe" in its description.
'''


def get_all_techniques(src):
    filt = [Filter('type', '=', 'attack-pattern')]
    return src.query(filt)


def get_technique_by_name(src, name):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('name', '=', name)
    ]
    return src.query(filt)


def get_techniques_by_content(src, content):
    techniques = get_all_techniques(src)
    return [
        tech for tech in techniques
        if content.lower() in tech.description.lower()
    ]


def get_techniques_since_time(src, timestamp):
    """
    Get Techniques added since a certain time

    get_techniques_since_time(src, "2018-10-01T00:14:20.652Z")

    This example shows how you can use the Filter API
    to only get techniques that have been added to the STIX content
    since a certain time based on the created timestamp.
    This code could be used within a larger function or script
    to alert when a new technique has been added to the ATT&CK STIX/TAXII content.
    The type could also be changed (or removed completely) to return results for different objects.
    """
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('created', '>', timestamp)
    ]
    return src.query(filt)


def get_object_by_attack_id(src, typ, attack_id):
    """
    Get any object by ATT&CK ID

    get_object_by_attack_id(fs, 'intrusion-set', 'G0016')

    In this example, the STIX 2.0 type must be passed into the function.
    Here we query for the group with ATT&CK ID G0016 (APT29).
    """
    filt = [
        Filter('type', '=', typ),
        Filter('external_references.external_id', '=', attack_id)
    ]
    return src.query(filt)


def get_group_by_alias(src, alias):
    """
    Get Group by alias

    get_group_by_alias(fs, 'Cozy Bear')[0]

    Here we query the group APT29 by one of its aliases.
    """
    return src.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])


# noinspection PyTypeChecker
def get_technique_by_group(src, stix_id):
    """
    Get all Techniques used by a Group

    group = get_group_by_alias(fs, 'Cozy Bear')[0]
    get_technique_by_group(fs, group)

    We query for the techniques that are directly connected to a group.
    This does NOT include techniques which are only used by the group's software.
    """
    relations = src.relationships(stix_id, 'uses', source_only=True)
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in relations])
    ])


# noinspection PyTypeChecker
def get_software_by_groups(src, group_stix_id):
    
    # get the malware, tools that the group uses
    group_uses = [
        r for r in src.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]

    # get the technique stix ids that the malware, tools use
    software_uses = src.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])
    
    software = src.query([
        Filter('type', '=', 'malware'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])
    
    software.extend(src.query([
        Filter('type', '=', 'tool'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ]))
    
    return software


# noinspection PyTypeChecker
def get_technique_users(src, tech_stix_id):
    """
    Get all Groups and Software that use a specific Technique

    tech = get_technique_by_name(fs, 'Rundll32')[0]
    get_technique_users(fs, tech.id)

    Notice that a relationship that uses an attack-pattern will always
    be target_ref for an intrusion-set, tool or malware. This example is broken down
    to separate groups from software, but it could have been made in a single step.
    """
    groups = [
        r.source_ref
        for r in src.relationships(tech_stix_id, 'uses', target_only=True)
        if get_type_from_id(r.source_ref) == 'intrusion-set'
    ]

    software = [
        r.source_ref
        for r in src.relationships(tech_stix_id, 'uses', target_only=True)
        if get_type_from_id(r.source_ref) in ['tool', 'malware']
    ]

    return src.query([
        Filter('type', 'in', ['intrusion-set', 'malware', 'tool']),
        Filter('id', 'in', groups + software)
    ])


def get_techniques_by_platform(src, platform):
    """
    Get all Techniques for specific platform

    get_techniques_by_platform(fs, 'Windows')

    Notice how the query is filtered by x_mitre_platforms using the = operator
    and a single platform, even though x_mitre_platforms is a list type.
    This means that for list properties, the = operator simply checks
    to see if the item is in the list.
    """
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('x_mitre_platforms', '=', platform)
    ])


def get_tactic_techniques(src, tactic):
    """
    Get all Techniques for specific Tactic

    get_tactic_techniques(fs, 'defense-evasion')

    You can also filter on sub-properties. In this example,
    we filter on the phase_name property within the kill_chain_phases property.
    """
    techs = src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', tactic)
    ])

    # double checking the kill chain is MITRE ATT&CK
    return [t for t in techs if {
        'kill_chain_name': 'mitre-attack',
        'phase_name': tactic,
    } in t.kill_chain_phases]


# noinspection PyTypeChecker
def get_mitigations_by_technique(src, tech_stix_id):
    """
    Get all Mitigations for specific Technique

    tech = get_technique_by_name(fs, 'Rundll32')[0]
    get_mitigations_by_technique(fs, tech.id)

    The mitigations for a technique are stored in objects separate
    from the technique. These objects are found through a mitigates relationship.
    """
    relations = src.relationships(tech_stix_id, 'mitigates', target_only=True)
    return src.query([
        Filter('type', '=', 'course-of-action'),
        Filter('id', 'in', [r.source_ref for r in relations])
    ])


def get_tactics_by_matrix(src):
    """
    Get all Tactics for Matrix
    
    The tactics are individual objects (x-mitre-tactic),
    and their order in a matrix (x-mitre-matrix) is found
    within the tactic_refs property in a matrix. The order of
    the tactics in that list matches the ordering of the tactics in that matrix.
    You can get all matrices and tactics in Enterprise ATT&CK
    (or in any other ATT&CK domain) by using the following code.
    """
    tactics = {}
    matrix = src.query([
        Filter('type', '=', 'x-mitre-matrix'),
    ])

    for i in range(len(matrix)):
        tactics[matrix[i]['name']] = []
        for tactic_id in matrix[i]['tactic_refs']:
            tactics[matrix[i]['name']].append(src.query([Filter('id', '=', tactic_id)])[0])

    return tactics


# noinspection PyTypeChecker
def get_revoked_by(stix_id, src):
    """
    Get an Object that revoked a previous Object

    If an object is revoked by another object,
    whether it's a group/software/technique/x-mitre-tactic/x-mitre-matrix,
    that means that the object was replaced by a new object.
    You can find what object replaced the original object
    by supplying the stix_id of the revoked object to the following function.
    """
    relations = src.relationships(stix_id, 'revoked-by', source_only=True)
    revoked_by = src.query([
        Filter('id', 'in', [r.target_ref for r in relations]),
        Filter('revoked', '=', False)
    ])
    if revoked_by is not None:
        revoked_by = revoked_by[0]

    return revoked_by


def get_software_group_mitigations(src, technique_id):
    """
    get software, groups and mitigations that are used in a specific technique
    """
    software, group, mitigation = [], [], []
    
    software_group = get_technique_users(src, technique_id)
    for elem in software_group:
        if elem['external_references'][0]['external_id'][0] == 'S':
            software.append(elem)
        elif elem['external_references'][0]['external_id'][0] == 'G':
            group.append(elem)

    mitigations = get_mitigations_by_technique(src, technique_id)
    for miti in mitigations:
        if miti['external_references'][0]['external_id'][0] == 'M':
            mitigation.append(miti)
    
    return software, group, mitigation
