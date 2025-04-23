import os.path

import matplotlib.pyplot as plt
import numpy as np
from os.path import dirname
from os import getcwd, stat
import pathlib
import json

def parse_cvss_vector(vector):
    return str.split(vector, "/")

def output(model, file_name):
    plt.savefig(dirname(getcwd()) + "\\04-product\\" + str(file_name))

def parse_grype_output(json_file):
    vulns = []
    with open(json_file) as in_file:
        grype_data = json.load(in_file)
        for match in grype_data['matches']:
            if 'cvss' in match['vulnerability'] and len(match['vulnerability']['cvss']) > 0:
                # has a CVSS, if not we need to check relatedVulns
                for cvss in match['vulnerability']['cvss']:
                    # only care about version 3.1
                    if cvss['version'] == "3.1":
                        vulns.append(Vuln(id=match['vulnerability']['id'], cvss_vector=cvss['vector'],
                                          base_score=cvss['metrics']['baseScore'],
                                          exploitability_score=cvss['metrics']['exploitabilityScore'],
                                          impact_score=cvss['metrics']['impactScore']))
            # had no cvss so we check related. Needs to be else if so we prioritize the case where cvss data exists
            elif 'relatedVulnerabilities' in match and len(match['relatedVulnerabilities']) > 0:
                # shorthand to clean up the
                for related_vuln in match['relatedVulnerabilities']:
                    if 'cvss' in related_vuln and len(related_vuln['cvss']) > 0:
                        for cvss in related_vuln['cvss']:
                            # only care about version 3.1
                            if cvss['version'] == "3.1":
                                vulns.append(Vuln(id=related_vuln['id'], cvss_vector=cvss['vector'],
                                          base_score=cvss['metrics']['baseScore'],
                                          exploitability_score=cvss['metrics']['exploitabilityScore'],
                                          impact_score=cvss['metrics']['impactScore']))
    return vulns

def generate_histograms(project_vulns):
    attack_vector_counts = {}
    attack_complexity_counts = {}
    privileges_required_counts = {}
    user_interaction_counts = {}
    scope_counts = {}
    confidentiality_counts = {}
    integrity_counts = {}
    availability_counts = {}
    for project in project_vulns:
        for vuln in project_vulns[project]:
            attack_vector = vuln.get_attack_vector()
            attack_vector_counts[attack_vector] = attack_vector_counts.get(attack_vector, 0) + 1
            attack_complexity = vuln.get_attack_complexity()
            attack_complexity_counts[attack_complexity] = attack_complexity_counts.get(attack_complexity, 0) + 1
            privileges_required = vuln.get_privileges_required()
            privileges_required_counts[privileges_required] = privileges_required_counts.get(privileges_required, 0) + 1
            user_interaction = vuln.get_user_interaction()
            user_interaction_counts[user_interaction] = user_interaction_counts.get(user_interaction, 0) + 1
            scope = vuln.get_scope()
            scope_counts[scope] = scope_counts.get(scope, 0) + 1
            confidentiality = vuln.get_confidentiality()
            confidentiality_counts[confidentiality] = confidentiality_counts.get(confidentiality, 0) + 1
            integrity = vuln.get_integrity()
            integrity_counts[integrity] = integrity_counts.get(integrity, 0) + 1
            availability = vuln.get_availability()
            availability_counts[availability] = availability_counts.get(availability, 0) + 1

    fig, axs = plt.subplots(4,2, figsize=(10,8))
    fig.suptitle("Histograms of CVSS 3.1 labels across Grype findings from the Cloud benchmark dataset (203 docker images)")
    axs[0,0].bar(attack_vector_counts.keys(), attack_vector_counts.values())
    axs[0,0].set_xlabel('Attack vector category')
    axs[0,0].set_ylabel('Frequency')
    axs[1,0].bar(attack_complexity_counts.keys(), attack_complexity_counts.values())
    axs[1,0].set_xlabel('Attack complexity category')
    axs[1,0].set_ylabel('Frequency')
    axs[2,0].bar(privileges_required_counts.keys(), privileges_required_counts.values())
    axs[2,0].set_xlabel('Privileges required category')
    axs[2,0].set_ylabel('Frequency')
    axs[3,0].bar(user_interaction_counts.keys(), user_interaction_counts.values())
    axs[3,0].set_xlabel('User interaction category')
    axs[3,0].set_ylabel('Frequency')
    axs[0,1].bar(scope_counts.keys(), scope_counts.values())
    axs[0,1].set_xlabel('Scope category')
    axs[0,1].set_ylabel('Frequency')
    axs[1,1].bar(confidentiality_counts.keys(), confidentiality_counts.values())
    axs[1,1].set_xlabel('Confidentiality category')
    axs[1,1].set_ylabel('Frequency')
    axs[2,1].bar(integrity_counts.keys(), integrity_counts.values())
    axs[2,1].set_xlabel('Integrity category')
    axs[2,1].set_ylabel('Frequency')
    axs[3,1].bar(availability_counts.keys(), availability_counts.values())
    axs[3,1].set_xlabel('Availability category')
    axs[3,1].set_ylabel('Frequency')
    plt.savefig('04-product/histograms.png')

def generate_violins(project_vulns):
    plt.figure()
    sample_data = np.random.normal(0, 1, (100, 3))
    print(sample_data)
    plt.violinplot(sample_data)
    plt.savefig("04-product/violins.png")

def cvss_analyzer(in_dir):
    root_dir = pathlib.Path(in_dir)
    project_vulns = {}
    for json_file in root_dir.rglob("*.json"):
        if json_file.is_file():
            # make sure it is grype, the parent dir has "grype in it, AND that it is not blank. Files will be blank
            # when Grype does not find any vulnerabilities in the project under analysis
            if ("grype" in json_file.name or "grype" in json_file.parent.name) and stat(json_file).st_size > 0:
                start_key = str.split(str.split(json_file.name, ".json")[0], "grype-")
                key = start_key[1] if len(start_key) == 2 else start_key[0]
                project_vulns[key] = parse_grype_output(json_file)

    generate_histograms(project_vulns)
    generate_violins(project_vulns)

class Vuln:
    def __init__(self, id, cvss_vector, base_score, exploitability_score, impact_score):
        self.id = id
        self.cvss_vector = cvss_vector
        self.base_score = base_score
        self.exploitability_score = exploitability_score
        self.impact_score = impact_score

    def get_attack_vector(self):
        return str.split(self.cvss_vector, "/")[1]

    def get_attack_complexity(self):
        return str.split(self.cvss_vector, "/")[2]

    def get_privileges_required(self):
        return str.split(self.cvss_vector, "/")[3]

    def get_user_interaction(self):
        return str.split(self.cvss_vector, "/")[4]

    def get_scope(self):
        return str.split(self.cvss_vector, "/")[5]

    def get_confidentiality(self):
        return str.split(self.cvss_vector, "/")[6]

    def get_integrity(self):
        return str.split(self.cvss_vector, "/")[7]

    def get_availability(self):
        return str.split(self.cvss_vector, "/")[8]

if __name__ == "__main__":
    in_dir = "01-input/tool-out"
    cvss_analyzer(in_dir)
