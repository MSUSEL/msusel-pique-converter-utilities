import sys
from bs4 import BeautifulSoup


def importXML(filename):
    with open(filename, 'r') as f:
        return BeautifulSoup(f.read(), "xml")


def getWeaknessFromID(cwe_id):
    weakness = weaknesses.find("Weakness", {"ID":cwe_id})
    return weakness


def main(filename):
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

                print(description)

class measureNode:
    def __init__(self, name, description, positive, children):
        self.name = name
        self.description = description
        self.positive = positive
        self.children = children

if __name__ == "__main__":
    main(sys.argv[1])
