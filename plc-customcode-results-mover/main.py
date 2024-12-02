import os
import shutil
import re

def main():
    output_dir = "output/"
    input_dir = "input/CodeSys-KEN-Results/"
    input_dir_ken = input_dir + str("KEN Results/KEN-output")
    input_dir_codesys = input_dir + str("SA_results/SA_results")
    ken_files = os.listdir(input_dir_ken)
    codesys_files = os.listdir(input_dir_codesys)

    for file in ken_files:
        source_path = os.path.join(input_dir_ken, file)
        project_dir = output_dir + str(os.path.splitext(file)[0])
        if not os.path.exists(project_dir):
            os.makedirs(project_dir)
        destination_path = os.path.join(project_dir, str("KEN-") + file)
        print(destination_path)
        shutil.move(source_path, destination_path)

    for file in codesys_files:
        source_path = os.path.join(input_dir_codesys, file)
        project_name_from_file = re.split("-", str(os.path.splitext(file)[0]))[0]
        project_dir = output_dir + project_name_from_file
        if not os.path.exists(project_dir):
            os.makedirs(project_dir)
        destination_path = os.path.join(project_dir, str("CodeSys-") + file)
        print(destination_path)
        shutil.move(source_path, destination_path)

if __name__ == "__main__":
    main()
