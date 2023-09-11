import os
import re
import argparse
import csv
import json
from pathlib import Path

# naming conventions built after the json they need to be exported to.
additionalData = {}

global_config = {
    "benchmark_strategy": "pique.calibration.MeanSDBenchmarker",
    "normalizer": "pique.evaluation.NoNormalizer",
    "weights_strategy": "calibration.BinaryCWEWeighter"
}

eval_strategies = {
    "quality_aspect": "evaluator.QualityAspectEvaluator",
    "product_factor": "evaluator.WeightedAverageEvaluator"
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


def build_product_factors_from_cwe_pillars(tree):
    # I need to do 2 things here: (1) find Pillars, assign them to CWE. (2) remove those pillars from the tree
    # find pillars



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
                                                         'and not CWE pillars as product factors which is default.',
                        default=False,
                        action='store_true')
    parser.add_argument('-qa', '--quality_aspects', help='Selection of quality aspect nodes. Two quality aspect '
                                                         'groups are included in this release, the ISO 25010 quality '
                                                         'aspects and the Microsoft STRIDE quality aspects. Options '
                                                         'are \'ISO\' for ISO 25010 and \'STRIDE\' for Microsoft '
                                                         'STRIDE. Default is ISO 25010', choices={'ISO', 'STRIDE'},
                        default='ISO')
    parser.add_argument('-v', '--version')
    args = parser.parse_args()
    extension = os.path.splitext(args.input_file)
    process = PARSE_FUNCTION_MAP[extension[1]]
    tree = process(args.input_file)
    tqi = build_tqi(args.name)
    quality_aspect_func = QUALITY_ASPECT_FUNCTION_MAP[args.quality_aspects]
    quality_aspects = quality_aspect_func()
    product_factors = {}
    if not args.custom_product_factors:
        product_factors = build_product_factors_from_cwe_pillars(tree)

    factors = FactorNode(tqi, quality_aspects, product_factors)

    model_definition = JSONRoot(args.name, additionalData, global_config, factors, list(tree.values()),
                                {"diagnostics": {}})
    export_to_json(args.output, model_definition)


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


class MeasureNode:
    def __init__(self, cwe_id, name, weakness_abstraction, description, children):
        self.cwe_id = cwe_id
        self.name = name
        self.positive = "false"
        self.weakness_abstraction = weakness_abstraction
        self.description = description
        self.children = children

    def __str__(self):
        return self.name + " Measure Node"


if __name__ == "__main__":
    main()
