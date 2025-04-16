import os
import json


def grype_parser(file):
    # project_info is a list of ["name", "tag"]
    project_name_tag = (os.path.splitext(os.path.basename(file))[0]).split(":")
    # grype vulns is a dict of type: {Finding obj : [Finding objs]}, where the dict value is a list of Finding object instances
    # representing the relatedVulnerabilities that Grype reports.
    grype_vulns = {}
    with open(file) as json_file:
        grype_data = json.load(json_file)
        for match in grype_data['matches']:
            # fill out CVSS data from Grype for primary vuln finding (NOT relatedVulnerability)
            cvsses = []
            if 'cvss' in match['vulnerability'] and len(match['vulnerability']['cvss']) > 0:
                # has a CVSS
                for cvss in match['vulnerability']['cvss']:
                    cvsses.append(grype_cvss_appender(cvss))
            # add related vulnerabilities
            related_vulnerabilities = []
            if 'relatedVulnerabilities' in match['vulnerability'] and len(
                    match['vulnerability']['relatedVulnerabilities']) > 0:
                for related_vulnerability in match['vulnerability']['relatedVulnerabilities']:
                    related_cvsses = []
                    if 'cvss' in related_vulnerabilities and len(related_vulnerabilities['cvss']) > 0:
                        # has a CVSS
                        for cvss in related_vulnerabilities['cvss']:
                            related_cvsses.append(grype_cvss_appender(cvss))
                    related_vulnerabilities.append(grype_finding_appender(related_vulnerability))
            # get location info
            artifacts = []
            grype_vulns{}
            # grype_vulns[grype_finding_appender(match['vulnerability'], project_name_tag[0], project_name_tag[1],
            #                                   cvsses, artifacts)] = related_vulnerabilities
    return grype_vulns


def grype_artifact_appender(artifact_json_obj):
    # id, name, version, type, Location
    return Artifact(artifact_json_obj['id'], artifact_json_obj['name'], artifact_json_obj['version'],
                    artifact_json_obj['type'])


def grype_finding_appender(vulnerability_json_obj, project_name, project_tag, cvsses, artifacts):
    # tool, project, project_tag, cve, cvsses, cwes, has_fix, location
    return Finding("grype", project_name, project_tag, vulnerability_json_obj['id'], cvsses, "not-supplied",
                   vulnerability_json_obj['fix']['state'], artifacts)


# quick little function to input a json object of type 'cvss' from Grype and output a CVSS object
def grype_cvss_appender(cvss_json_obj):
    return CVSS(cvss_json_obj['source'], cvss_json_obj['version'], cvss_json_obj['vector'], "not-supplied",
                cvss_json_obj['metrics']['baseScore'], cvss_json_obj['metrics']['exploitabilityScore'],
                cvss_json_obj['metrics']['impactScore'])


def output(file_name, grype_vulns):
    with open(file_name, 'w') as out_file:
        print(json.dumps(grype_vulns, indent=2, cls=CustomEncoder), file=out_file)


class Finding:
    # cvsses is a dict of {"list of objects of class CVSS (defined in this file), cwes is a list of strings,
    # artifact is a single instance of object Artifact (defined in this file) and everything else is a string.
    # Note that has_fix can be considered an enum, but it comes from the tools and we treat it as a string
    def __init__(self, tool, project, project_tag, cve, cvsses, cwes, has_fix, artifact):
        self.tool = tool
        self.project = project
        self.project_tag = project_tag
        self.cve = cve
        self.cvsses = cvsses
        self.cwes = cwes
        self.has_fix = has_fix
        self.artifact = artifact


class CVSS:
    # data class to capture CVSS data; for the most part these fields are standard across Grype and Trivy, but
    # Trivy results include a RedHat security ranking and do not have baseScore, exploitabilityScore, or impactScore.
    # In the case of associating the two tools, it appears (tm) that Grype's baseScore matches Trivy's assigned_score
    def __init__(self, source, version, vector, assigned_score, baseScore, exploitabilityScore, impactScore):
        self.source = source
        self.version = version
        self.vector = vector
        self.assigned_score = assigned_score
        self.base_score = baseScore
        self.exploitability_score = exploitabilityScore
        self.impact_score = impactScore

    def get_vector_components(self):
        split = self.vector.split("/")
        if split[0] == 'CVSS:3.1':
            split = split[1:len(split)]
        return split

    # split a cvss vector of form "AV:N/AC:L/Au:N/C:P/I:P/A:P" -or- "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" into
    # a list of components, such as ["AV:N", "AC:L", "Au:N", "C:P", "I:P", "A:P"]


class Artifact:
    # data class to capture artifact data of a finding. Grype provides a type and Trivy does not.
    # Otherwise, the fields are consistently named
    def __init__(self, id, name, version, type):
        self.id = id
        self.name = name
        self.version = version
        self.type = type


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        return obj.__dict__


# This script is intended to scrape the data from trivy, grype, and dive reports into one file for continual analysis
def main():
    grype_vulns = grype_parser("01-input/tool-out/alpine/grype-alpine:3.11.8.json")
    output("03-incremental/output.json", grype_vulns)


if __name__ == "__main__":
    main()
