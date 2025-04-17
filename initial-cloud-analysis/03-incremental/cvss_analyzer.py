import os.path

import matplotlib.pyplot as plt
import numpy as np
from os.path import dirname
from os import getcwd, stat
import pathlib
import json

def get_data():
    data = [np.random.normal(0, std, 100) for std in range(1, 4)]
    fig, ax = plt.subplots()
    ax.violinplot(data)
    return data

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
    for project in project_vulns:
        attack_vector = project.get_attack_vector()
        print(project)
        attack_vector_counts[attack_vector] = attack_vector_counts.get(attack_vector, 0) + 1

    print(attack_vector_counts)


def cvss_analyzer(in_dir):
    root_dir = pathlib.Path(in_dir)
    project_vulns = {}
    for json_file in root_dir.rglob("*random.json"):
        if json_file.is_file():
            # make sure it is grype, the parent dir has "grype in it, AND that it is not blank. Files will be blank
            # when Grype does not find any vulnerabilities in the project under analysis
            if ("grype" in json_file.name or "grype" in json_file.parent.name) and stat(json_file).st_size > 0:
                start_key = str.split(str.split(json_file.name, ".json")[0], "grype-")
                key = start_key[1] if len(start_key) == 2 else start_key[0]
                project_vulns[key] = parse_grype_output(json_file)


    generate_histograms(project_vulns)
    data = get_data()
    output(data, "output.png")

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

if __name__ == "__main__":
    in_dir = "01-input/tool-out"
    cvss_analyzer(in_dir)
