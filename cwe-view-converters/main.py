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


def build_quality_aspects():
    quality_aspects = {

    }


def main():
    FUNCTION_MAP = {'.xml': parse_xml,
                    '.csv': parse_csv}
    parser = argparse.ArgumentParser(
        prog='main.py',
        description='This script converts a CWE view to a PIQUE model definition. '
                    'Input is a xml or csv file (exported from the MITRE CWE database), '
                    'output is a partial PIQUE model definition file',
    )
    parser.add_argument('-i', '--input_file', help='input filename, absolute or relative filepath')
    parser.add_argument('-m', '--model_name', help='name of the model')
    parser.add_argument('-o', '--output', help='output filename, extension will be generated')
    parser.add_argument('-qa', '--quality_aspects', help='Selection of quality aspect nodes. Two quality aspect '
                                                         'groups are included in this release, the ISO 25010 quality '
                                                         'aspects and the Microsoft STRIDE quality aspects. Options '
                                                         'are \'ISO\' for ISO 25010 and \'STRIDE\' for Microsoft '
                                                         'STRIDE. Default is ISO 25010', choices={'ISO', 'STRIDE'})
    parser.add_argument('-v', '--version')
    args = parser.parse_args()
    extension = os.path.splitext(args.input_file)
    process = FUNCTION_MAP[extension[1]]
    tree = process(args.input_file)

    tqi = build_tqi(args.model_name)

    factors = FactorNode(tqi, {}, {})

    model_definition = JSONRoot(args.model_name, additionalData, global_config, factors, list(tree.values()),
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
