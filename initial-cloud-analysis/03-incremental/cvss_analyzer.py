import matplotlib.pyplot as plt
import numpy as np
import os


def get_data():
    data = [np.random.normal(0, std, 100) for std in range(1, 4)]
    fig, ax = plt.subplots()
    ax.violinplot(data)
    return data

def output(model, file_name):
    plt.savefig(os.path.dirname(os.getcwd()) + "\\04-product\\" + str(file_name))

def cvss_analyzer():
    data = get_data()
    output(data)


if __name__ == "__main__":
    cvss_analyzer()