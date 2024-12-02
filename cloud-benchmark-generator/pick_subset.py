import sys
import json
import random
import os


def pick_subset(file_name, selection_number):
    # load existing json file
    with open(file_name, 'r') as f:
        json_input = f.read()
    data = json.loads(json_input)

    for image in data['images']:
        # remove if thought necessary
        random.seed(11235813)
        #random.sample pulls with NO replacement
        new_tags = random.sample(image['versions'], int(selection_number))
        # update original data with this deep replacement
        image['versions'] = new_tags

    # create output file path from old filename
    file_name_no_extension = os.path.splitext(file_name)[0]
    with open(file_name_no_extension + '-' + selection_number + '.json', 'w') as f_out:
        # export to json
        json.dump(data, f_out, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("supply more arguments, program is meant to be run as: <python> pick_subset.py <name of file> <number of projects to RANDOMLY select>")
        sys.exit(0)
    if len(sys.argv) > 3:
        print("supply fewer arguments, program is meant to be run as: <python> pick_subset.py <name of file> <number of projects to RANDOMLY select>")
        sys.exit(0)
    pick_subset(sys.argv[1], sys.argv[2])