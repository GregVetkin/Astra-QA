import pytest
import subprocess
import os


def pwd(params=[]):
    try:
        command = ["pwd"]
        command += params
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print("An error occurred:", e)
        return None
    


def test_pwd_current_dir():
    assert pwd() == os.getcwd()


@pytest.mark.parametrize("dir", [
    ("/"),
    ("/var"),
    ("/tmp"),
])
def test_pwd_common_dir(dir):
    os.chdir(dir)
    assert pwd() == dir



@pytest.fixture(scope="function")
def create_dir():
    dir = "/test/some/created/dir"
    os.makedirs(dir, exist_ok=True)
    os.chdir(dir)

    yield

    os.chdir("/")
    os.removedirs(dir)


def test_pwd_created_dir(create_dir):
    assert pwd() == os.getcwd()



@pytest.fixture(scope="function")
def create_symbolic_link():
    dir_path_1 = "/test"
    dir_path_2 = "/test2"
    link_path  = f"{dir_path_1}/link"

    os.makedirs(dir_path_1, exist_ok=True)
    os.makedirs(dir_path_2, exist_ok=True)
    os.symlink(dir_path_2, link_path)
    os.chdir(link_path)

    yield

    os.chdir("/")
    os.remove(link_path)
    os.removedirs(dir_path_1)
    os.removedirs(dir_path_2)


def test_pwd_actual_link_path(create_symbolic_link):
    assert pwd() == "/test2"

def test_pwd_physical_link_path(create_symbolic_link):
    assert pwd(["-P"]) == "/test2"