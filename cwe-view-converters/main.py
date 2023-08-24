import sys
import argparse
from bs4 import BeautifulSoup



def importXML(filename):
    with open(filename, encoding="utf-8") as f:
        return BeautifulSoup(f.read(), "xml")


def getWeaknessFromID(cwe_id):
    weakness = weaknesses.find("Weakness", {"ID":cwe_id})
    return weakness


def parse_xml(filename):
    print("parse xml")
    exit()
    data = importXML(filename)
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

                weaknesses.update({cwe_id: measureNode(name, description, positive, parents)})

                # print(description)

class measureNode:
    def __init__(self, name, description, positive, parents):
        self.name = name
        self.description = description
        self.positive = positive
        self.parents = parents

def parse_csv():
    print("in parse csv")

def main():
    FUNCTION_MAP = {'xml': parse_xml,
                    'csv': parse_csv}
    parser = argparse.ArgumentParser(
        prog='main.py',
        description='This script converts a CWE view to a PIQUE model definition. Input is a xml or csv file (exported from the MITRE CWE database), output is a partial PIQUE model definition file',
    )
    parser.add_argument('-f', '--format', help='input format type [xml, csv]', choices=FUNCTION_MAP.keys())
    parser.add_argument('-i', '--input_file', help='input filename, absolute or relative filepath')
    parser.add_argument('-o', '--output', help='output filename, extension will be generated')
    parser.add_argument('-v', '--version')
    args = parser.parse_args()

    if args["format"]:
        print("format")

if __name__ == "__main__":
    main()


