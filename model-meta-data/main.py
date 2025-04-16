import os, json





def main():
    json_files = [pos_json for pos_json in os.listdir('input') if pos_json.endswith('.json')]

if __name__ == "__main__":
    main()