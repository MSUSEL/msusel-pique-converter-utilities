import os.path

import matplotlib.pyplot as plt
import numpy as np
from os.path import dirname
from os import getcwd, stat
import pathlib
import json
from collections import defaultdict

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
    plt.savefig('04-product/histograms.pdf')


def generate_base_score_violin(project_vulns, score_types):
    plt.figure()

    y_counter = 0
    fig, axs = plt.subplots(3,8, figsize=(22,17))
    fig.suptitle("Violin plots of CVSS 3.1 scores (separated by CVSS attack categories) across Grype findings from the Cloud benchmark dataset (203 docker images)")
    fig.supylabel('CVSS 3.1 Base Score')
    for score_type in score_types:

        attack_vector_score = defaultdict(list)
        attack_complexity_score = defaultdict(list)
        privileges_required_score = defaultdict(list)
        user_interaction_score = defaultdict(list)
        scope_score = defaultdict(list)
        confidentiality_score = defaultdict(list)
        integrity_score = defaultdict(list)
        availability_score = defaultdict(list)

        for project in project_vulns:
            for vuln in project_vulns[project]:
                attack_vector = vuln.get_attack_vector()
                attack_vector_score[attack_vector].append(getattr(vuln, score_type))
                attack_complexity = vuln.get_attack_complexity()
                attack_complexity_score[attack_complexity].append(getattr(vuln, score_type))
                privileges_required = vuln.get_privileges_required()
                privileges_required_score[privileges_required].append(getattr(vuln, score_type))
                user_interaction = vuln.get_user_interaction()
                user_interaction_score[user_interaction].append(getattr(vuln, score_type))
                scope = vuln.get_scope()
                scope_score[scope].append(getattr(vuln, score_type))
                confidentiality = vuln.get_confidentiality()
                confidentiality_score[confidentiality].append(getattr(vuln, score_type))
                integrity = vuln.get_integrity()
                integrity_score[integrity].append(getattr(vuln, score_type))
                availability = vuln.get_availability()
                availability_score[availability].append(getattr(vuln, score_type))

        attack_vector_data = list(attack_vector_score.values())
        attack_vector_labels = list(attack_vector_score.keys())
        attack_complexity_data = list(attack_complexity_score.values())
        attack_complexity_labels = list(attack_complexity_score.keys())
        privileges_required_data = list(privileges_required_score.values())
        privileges_required_labels = list(privileges_required_score.keys())
        user_interaction_data = list(user_interaction_score.values())
        user_interaction_labels = list(user_interaction_score.keys())
        scope_data = list(scope_score.values())
        scope_labels = list(scope_score.keys())
        confidentiality_data = list(confidentiality_score.values())
        confidentiality_labels = list(confidentiality_score.keys())
        integrity_data = list(integrity_score.values())
        integrity_labels = list(integrity_score.keys())
        availability_data = list(availability_score.values())
        availability_labels = list(availability_score.keys())

        axs[y_counter, 0].violinplot(attack_vector_data, positions=range(len(attack_vector_labels)))
        axs[y_counter, 0].set_xlabel('Attack vector category')
        axs[y_counter, 0].set_xticks(range(len(attack_vector_labels)))
        axs[y_counter, 0].set_xticklabels(attack_vector_labels)

        axs[y_counter, 1].violinplot(attack_complexity_data, positions=range(len(attack_complexity_labels)))
        axs[y_counter, 1].set_xlabel('Attack complexity category')
        axs[y_counter, 1].set_xticks(range(len(attack_complexity_labels)))
        axs[y_counter, 1].set_xticklabels(attack_complexity_labels)

        axs[y_counter, 2].violinplot(privileges_required_data, positions=range(len(privileges_required_labels)))
        axs[y_counter, 2].set_xlabel('Privileges required category')
        axs[y_counter, 2].set_xticks(range(len(privileges_required_labels)))
        axs[y_counter, 2].set_xticklabels(privileges_required_labels)

        axs[y_counter, 3].violinplot(user_interaction_data, positions=range(len(user_interaction_labels)))
        axs[y_counter, 3].set_xlabel('User interaction category')
        axs[y_counter, 3].set_xticks(range(len(user_interaction_labels)))
        axs[y_counter, 3].set_xticklabels(user_interaction_labels)

        axs[y_counter, 4].violinplot(scope_data, positions=range(len(scope_labels)))
        axs[y_counter, 4].set_xlabel('Scope category')
        axs[y_counter, 4].set_xticks(range(len(scope_labels)))
        axs[y_counter, 4].set_xticklabels(scope_labels)

        axs[y_counter, 5].violinplot(confidentiality_data, positions=range(len(confidentiality_labels)))
        axs[y_counter, 5].set_xlabel('Confidentiality category')
        axs[y_counter, 5].set_xticks(range(len(confidentiality_labels)))
        axs[y_counter, 5].set_xticklabels(confidentiality_labels)

        axs[y_counter, 6].violinplot(integrity_data, positions=range(len(integrity_labels)))
        axs[y_counter, 6].set_xlabel('Integrity category')
        axs[y_counter, 6].set_xticks(range(len(integrity_labels)))
        axs[y_counter, 6].set_xticklabels(integrity_labels)

        axs[y_counter, 7].violinplot(availability_data, positions=range(len(availability_labels)))
        axs[y_counter, 7].set_xlabel('Availability category')
        axs[y_counter, 7].set_xticks(range(len(availability_labels)))
        axs[y_counter, 7].set_xticklabels(availability_labels)

        axs[y_counter, 0].set_ylabel(str(score_type))
        y_counter = y_counter+1
    plt.savefig("04-product/violins.png")
    plt.savefig("04-product/violins.pdf")

def generate_violins(project_vulns):
    plt.figure()

    score_types = ["base_score", "exploitability_score", "impact_score"]

    generate_base_score_violin(project_vulns, score_types)


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
