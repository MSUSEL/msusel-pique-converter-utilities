import os
import re
import argparse
import csv
import json
from pathlib import Path

# naming conventions built after the json they need to be exported to.
additionalData = {}

global_config = {
    "benchmark_strategy": "pique.calibration.NaiveBenchmarker",
    "normalizer": "pique.evaluation.NoNormalizer",
    "weights_strategy": "pique.calibration.NaiveWeighter"
}

eval_strategies = {
    "quality_aspect": "pique.evaluation.DefaultFactorEvaluator",
    "product_factor": "pique.evaluation.DefaultProductFactorEvaluator"
}


def parse_xml(input_file):
    print("Not yet implemented")
    exit(0)


def export_to_json(output_file, model_definition):
    class ComplexEncoder(json.JSONEncoder):
        def default(self, obj):
            return obj.__dict__

    with open(output_file, "w", encoding="utf8") as json_output:
        print(json.dumps(model_definition, indent=2, cls=ComplexEncoder), file=json_output)
    print("Output finished, view the generated model definition at path: " + output_file)


def build_tqi(model_name):
    tqi = {model_name: {
        "description": "Model description, replace with a description of your model"
    }
    }
    return tqi


def build_iso_quality_aspects():
    quality_aspects = {
        "Functional Suitability": {
            "description": "Degree to which a product or system provides functions that meet stated and implied needs "
                           "when used under specified conditions",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Performance Efficiency": {
            "description": "Performance relative to the amount of resources used under stated conditions",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Usability": {
            "description": "Degree to which a product or system can be used by specified users to achieve specified "
                           "goals with effectiveness, efficiency and satisfaction in a specified context of use",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Compatibility": {
            "description": "Degree to which a product, system or component can exchange information with other "
                           "products, systems or components, and/or perform its required functions, while sharing the "
                           "same hardware or software environment",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Reliability": {
            "description": "Degree to which a system, product or component performs specified functions under "
                           "specified conditions for a specified period of time",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Security": {
            "description": "Degree to which a product or system protects information and data so that persons or "
                           "other products or systems have the degree of data access appropriate to their types and "
                           "levels of authorization",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Maintainability": {
            "description": "Degree of effectiveness and efficiency with which a product or system can be modified by "
                           "the intended maintainers",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Portability": {
            "description": "degree of effectiveness and efficiency with which a system, product or component can be "
                           "transferred from one hardware, software or other operational or usage environment to "
                           "another",
            "eval_strategy": eval_strategies['quality_aspect']
        }
    }
    return quality_aspects


def build_stride_quality_aspects():
    quality_aspects = {
        "Confidentiality": {
            "description": "Information is not made available or disclosed to unauthorized individuals, entities, "
                           "or processes.",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Integrity": {
            "description": "Data or processes cannot be modified in an unauthorized way.",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Availability": {
            "description": "Data and processes should be available at all times when deemed necessary.",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Authenticity": {
            "description": "Identity of individuals, entities, or processes is verified correctly.",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Authorization": {
            "description": "individuals, entities, or processes only have access to data and processes they should.",
            "eval_strategy": eval_strategies['quality_aspect']
        },
        "Non-repudiation": {
            "description": "Individuals, entities, or processes may not deny any actions they performed.",
            "eval_strategy": eval_strategies['quality_aspect']
        }
    }
    return quality_aspects


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
            # careful here because the 'childof' tag refers to parents.
            # CWE 699 will use the keyword 'MemberOf'
            parent_ids = parse_relationship(related_weaknesses, "ChildOf", filename)
            tree.update({id: CWENode(id, name, weakness_abstraction, description, parent_ids, [])})
    return tree


def build_product_factors_from_cwe_pillars(tree):
    # I need to do 2 things here: (1) find Pillars, assign them to CWE. (2) remove those pillars from the tree
    # find pillars
    product_factors = {}
    for node in tree.values():
        if len(node.parents) == 0:
            # convert node.children to dict
            children_dict = {element: {} for index, element in enumerate(node.children)}
            product_factors.update({node.weakness_abstraction + " " + node.cwe_id: ProductFactorNode(node.name,
                                                                                                     node.description,
                                                                                                     eval_strategies[
                                                                                                         'product_factor'],
                                                                                                     children_dict)})
    return product_factors


def build_measures_from_cwe_tree(tree):
    measures = {}
    for node in tree.values():
        children_dict = {element: {} for index, element in enumerate(node.children)}
        measures.update(
            {node.cwe_id: MeasureNode(node.name, node.weakness_abstraction, node.description, children_dict)})
    return measures

def recursively_reassign_parent_to_squash(pf, measures, dict_child_ids):
    if not dict_child_ids:
        return
    for cwe_id in list(dict_child_ids):
        # we know we want to add these to pf's children, first iteration will be redundant.
        pf.children.update({cwe_id: {}})
        new_children = measures[cwe_id].children
        recursively_reassign_parent_to_squash(pf, measures, new_children)

def squash_measures(product_factors, measures):
    for pf in product_factors.values():
        recursively_reassign_parent_to_squash(pf, measures, pf.children)
        print(len(pf.children))
    # remove children measures
    for measure in measures.values():
        measure.children = {}
    return measures

def build_diagnostics_from_measures(measures, number_of_tools):
    diagnostics = {}
    for tool_id in range(int(number_of_tools)):
        tool_name_id = "tool-name-" + str(tool_id)
        for cwe_id in measures.keys():
            diagnostic_name = cwe_id + " Diagnostic " + tool_name_id
            diagnostics.update(
                {diagnostic_name: {"toolName": tool_name_id, "description": "Sum of findings of type " + cwe_id}})
            # after building the diagnostic node I still need to add the node as the child of the measure
            measures[cwe_id].children.update({diagnostic_name: {}})
    return diagnostics


def stitch_together_children(tree):
    for node in tree.values():
        for parentNode in node.parents:
            tree[parentNode].children.append(node.cwe_id)


def main():
    PARSE_FUNCTION_MAP = {'.xml': parse_xml,
                          '.csv': parse_csv}
    QUALITY_ASPECT_FUNCTION_MAP = {'ISO': build_iso_quality_aspects,
                                   'STRIDE': build_stride_quality_aspects}
    parser = argparse.ArgumentParser(
        prog='main.py',
        description='This script converts a CWE view to a PIQUE model definition. '
                    'Input is a xml or csv file (exported from the MITRE CWE database), '
                    'output is a partial PIQUE model definition file',
    )
    parser.add_argument('-i', '--input_file', help='input filename, absolute or relative filepath')
    parser.add_argument('-n', '--name', help='name of the model', default="UNNAMED MODEL")
    parser.add_argument('-o', '--output', help='output filename, extension will be generated')
    parser.add_argument('--custom_product_factors', help='True/False flag to specify if the quality model '
                                                         'should be generated using custom product factors, '
                                                         'and not CWE pillars as product factors which is default. Default is false.',
                        default=False,
                        action='store_true')
    parser.add_argument('-qa', '--quality_aspects', help='Selection of quality aspect nodes. Two quality aspect '
                                                         'groups are included in this release, the ISO 25010 quality '
                                                         'aspects and the Microsoft STRIDE quality aspects. Options '
                                                         'are \'ISO\' for ISO 25010 and \'STRIDE\' for Microsoft '
                                                         'STRIDE. Default is ISO 25010', choices={'ISO', 'STRIDE'},
                        default='ISO')
    parser.add_argument('-s', '--squash', help='True/False flag to specify if the quality model should be squashed; '
                                               'that is, a squashed model ensures that the layer of measures is only 1 node deep. '
                                               'When the CWE view has multiple layers (such as CWE-1000), the measures layer will consist '
                                               'of every CWE in 1000, and their parents will be the respective pillar from the view.',
                        default=False,
                        action='store_true')
    parser.add_argument('-t', '--number_of_tools',
                        help='The number of tools you are using in your model, as an integer. This number dictates '
                             'the number of diagnostic nodes that are produced, and each diagnostic node is linked to '
                             'a tool directly. For example, if you supply 2 for this argument, you will receive each '
                             'Diagnostic twice. Each Diagnostic will be named as '
                             '\'Diagnostic-<Diagnostic ID>-tool-name-<tool_number>\'. Default value is 1.',
                        default=1)
    parser.add_argument('-v', '--version')
    args = parser.parse_args()
    extension = os.path.splitext(args.input_file)
    process = PARSE_FUNCTION_MAP[extension[1]]
    # tree is a tree of CWENodes, NOT of MeasureNodes
    tree = process(args.input_file)
    # the parsing process returns nodes with a parent id, not a child id which is needed for PIQUE.
    stitch_together_children(tree)
    tqi = build_tqi(args.name)
    quality_aspect_func = QUALITY_ASPECT_FUNCTION_MAP[args.quality_aspects]
    quality_aspects = quality_aspect_func()
    product_factors = {}
    if not args.custom_product_factors:
        product_factors = build_product_factors_from_cwe_pillars(tree)
    factors = FactorNode(tqi, quality_aspects, product_factors)
    measures = build_measures_from_cwe_tree(tree)
    if args.squash:
        measures = squash_measures(product_factors, measures)
    diagnostics = build_diagnostics_from_measures(measures, args.number_of_tools)
    model_definition = JSONRoot(args.name, additionalData, global_config, factors, measures, diagnostics)
    export_to_json(args.output, model_definition)


class CWENode:
    def __init__(self, cwe_id, name, weakness_abstraction, description, parents, children):
        self.cwe_id = "CWE-" + cwe_id
        self.name = name
        self.weakness_abstraction = weakness_abstraction
        self.description = description
        self.parents = parents
        self.children = children


class JSONRoot:
    def __init__(self, name, additional_data, global_config, factors, measures, diagnostics):
        self.name = name
        self.additionalData = additional_data
        self.global_config = global_config
        self.factors = factors
        self.measures = measures
        self.diagnostics = diagnostics

    def __str__(self):
        return self.name


class FactorNode:
    def __init__(self, tqi, quality_aspects, product_factors):
        self.tqi = tqi
        self.quality_aspects = quality_aspects
        self.product_factors = product_factors


class ProductFactorNode:
    def __init__(self, name, description, eval_strategy, children):
        self.name = name
        self.description = description
        self.eval_strategy = eval_strategy
        self.children = children


class MeasureNode:
    def __init__(self, name, weakness_abstraction, description, children):
        self.name = name
        self.positive = "false"
        self.weakness_abstraction = weakness_abstraction
        self.description = description
        self.children = children

    def __str__(self):
        return self.name + " Measure Node"


if __name__ == "__main__":
    main()
