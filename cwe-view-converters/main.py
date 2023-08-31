import sys
import re
import argparse
import csv
from bs4 import BeautifulSoup
from pathlib import Path


def importXML(filename):
    with open(filename, encoding="utf-8") as f:
        return BeautifulSoup(f.read(), "xml")


def getWeaknessFromID(cwe_id):
    weakness = weaknesses.find("Weakness", {"ID": cwe_id})
    return weakness


def parse_xml(input_file):
    print("parse xml")
    exit()
    data = importXML(input_file)
    global views
    views = data.find_all('Views')
    global weaknesses
    weaknesses = data.find('Weaknesses')
    # more often than not, the input xml file will have only 1 view, but I am generalizing it just in case...
    for view in views:
        for member in view.find_all('Members'):
            for has_member in member.find_all('Has_Member'):
                cwe_id = has_member['CWE_ID']
                weakness = getWeaknessFromID(cwe_id)
                name = weakness['Name']
                description = weakness.find('Description')
                positive = False
                for related_weakness in weakness.find_all('Related_Weaknesses'):
                    print(related_weakness.find['CWE_ID'])
                parents = ""

                weaknesses.update({cwe_id: MeasureNode(name, description, positive, parents)})

                # print(description)


class MeasureNode:
    def __init__(self, cwe_id, name, weakness_abstraction, description, children_ids):
        self.cwe_id = cwe_id
        self.name = name
        self.weakness_abstraction = weakness_abstraction
        self.description = description
        self.children_ids = children_ids


# MITRES's CWE csv export does not include parent info, just children info. Not sure about the xml yet..
def parse_relationship(related_weaknesses, relationship, filename):
    # double colon delineated, this regex handles it
    children_ids = []
    # only match on the view id coming from the filename. This ensures we get the correct child for the CWE view
    for related_weaknesses_iter in re.finditer('::NATURE:' + relationship + ':CWE ID:(.\d*):VIEW ID:' + filename,
                                               related_weaknesses):
        children_ids.append(related_weaknesses_iter.group(1))
    return children_ids


def parse_csv(input_file):
    tree = {}
    with open(input_file, encoding="utf8") as csvfile:
        filename = Path(input_file).stem
        csv_reader = csv.reader(csvfile, delimiter=',')
        next(csv_reader, None)  # skip the headers
        for row in csv_reader:
            id = row[0]
            name = row[1]
            weakness_abstraction = row[2]
            description = row[4]
            related_weaknesses = row[6]
            children_ids = parse_relationship(related_weaknesses, "ChildOf", filename)
            tree.update({id: MeasureNode(id, name, weakness_abstraction, description, children_ids)})
    return tree

def main():
    FUNCTION_MAP = {'xml': parse_xml,
                    'csv': parse_csv}
    parser = argparse.ArgumentParser(
        prog='main.py',
        description='This script converts a CWE view to a PIQUE model definition. '
                    'Input is a xml or csv file (exported from the MITRE CWE database), '
                    'output is a partial PIQUE model definition file',
    )
    parser.add_argument('-f', '--format', help='input format type [xml, csv]', choices=FUNCTION_MAP.keys())
    parser.add_argument('-i', '--input_file', help='input filename, absolute or relative filepath')
    parser.add_argument('-o', '--output', help='output filename, extension will be generated')
    parser.add_argument('-v', '--version')
    args = parser.parse_args()
    process = FUNCTION_MAP[args.format]
    tree = process(args.input_file)

    for id in tree.keys():
        if len(tree[id].children_ids) == 0:
            print(id)


if __name__ == "__main__":
    main()
