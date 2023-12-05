from selenium import webdriver

projects = [
    "alpine"
]


def main():
    driver = webdriver.Chrome('./chromedriver')
    for project in projects:
        webpage = "https://hub.docker.com/_/" + project + "/tags"
        print(webpage)


if __name__ == "__main__":
    main()