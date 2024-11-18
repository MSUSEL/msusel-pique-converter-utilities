import os
import time
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait

projects = [
    "nginx"
]


def export_to_json(master_map):
    if not os.path.exists("out/"):
        os.makedirs("out/")
    with open('out/docker-projects-'+ projects[0] + '-benchmark.json', "w") as outfile:
        json.dump(master_map, outfile, indent=2)


def main():
    driver = webdriver.Chrome()
    wait = WebDriverWait(driver, 10)
    master_map = {'images': []}
    for project in projects:
        project_versions = []
        webpage = "https://hub.docker.com/_/" + project + "/tags"
        driver.get(webpage)
        time.sleep(6)
        #page counter, start at 2 because page 1 is the default tags page
        page_increment = 2;
        while True:
            # base case, this is a bit of a do-while loop
            final_page_elements = driver.find_elements(By.XPATH, "//div[@class='MuiTypography-root MuiTypography-subtitle1 css-13vrtj1']")
            if len(final_page_elements) > 0 and final_page_elements[0].text == "Tags not retrieved":
                break
            versions = driver.find_elements(By.XPATH, "//a[@class='MuiTypography-root MuiTypography-inherit MuiLink-root MuiLink-underlineAlways css-162qm3z' and @data-testid='navToImage']")
            for element in versions:
                # ignore latest, because latest is a duplicate of the one after latest
                if element.text != 'latest':
                    project_versions.append(element.text)
                    print(element.text)
            next_page = webpage + "?page=" + str(page_increment)
            driver.get(next_page)
            # wait for page to load
            time.sleep(3)
            page_increment += 1
        master_map['images'].append({"name":project, "versions": project_versions})
    driver.quit()
    export_to_json(master_map)


if __name__ == "__main__":
    main()
