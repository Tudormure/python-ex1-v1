import argparse #pentru a secventia codului
import os #pentru a interactiona cu fisiere
import ast #pentru a analiza secventele de cod
import subprocess #pentru a rula 
from typing import List, Set #liste si seturi
import requests #pentru API

def clone_repos(url_git: str, local: str) -> str: #clonam local repository-ul
    if not url_git.endswith(".git"):
        url_git = url_git + ".git" 
    name = url_git.split("/")[-1].replace(".git", "") #ia ultimul element din url (ex. repo.git) si extrage doar numele (repo)
    path = os.path.join(local,name) 
    subprocess.run(["git","clone", url_git,path], check = True)
    return path

def find_imports(path: str) -> Set[str]: 
    with open(path, 'r') as file:
        tree = ast.parse(file.read(),filename=path) 
    imports = set()
    for node in ast.walk(tree): #itereaza prin toate nodurile arborelui
        if isinstance(node, ast.Import): #cand ajunge la nod de tip imporrt
            imports.update(alias.name for alias in node.names) #setul ia numele importurilor
        elif isinstance(node, ast.ImportFrom): # cand ajunge la node de tip "from..import.." 
            if node.module:
                imports.add(node.module.split('.')[0]) #adauga setului numele modulului
    return imports

def analyze_project(path:str) -> Set[str]:
    imported = set() 
    for root, _, files in os.walk(path): #itereaza print toate tuplurile geenrate de os.walk(path)
        for file in files : #fiecare fisier in parte
            if file.endswith(".py"): #daca e fisier de tip python
                file_path = os.path.join(root, file) #calea intreaga a fisierului
                imported.update(find_imports(file_path)) #adauga setului importurile
    return imported

def check_security(libraries: Set[str])->List[str]:
    vulnerable_libraries = []
    for lib in libraries: #itereaza fiecare librarie in parte
        response = requests.get(f"https://pypi.org/pypi/{lib}/json") #date despre librarie
        if response.status_code == 200: #daca a functionat request-ul
            data = response.json()
            if "vulnerabilities" in data.get("info",{}): #cauta vulnerabilitati
                vulnerabilities = data["info"]["vulnerabilities"]
                if vulnerabilities: #daca exista vulnerabilitati
                    vulnerable_libraries.append(f"{lib}: {vulnerabilities}") #adauga in lista
    return vulnerable_libraries

def main():
    """
    Main function to parse command-line arguments and execute the analysis.
    """
    parser = argparse.ArgumentParser(description="Analyze Python projects from GitHub.")
    parser.add_argument("github_url", help="The URL of the GitHub repository to analyze.")  # Accept GitHub URL
    args = parser.parse_args()  # Parse arguments

    destination = "./cloned_repos"  # Directory to store cloned repositories
    os.makedirs(destination, exist_ok=True)  # Create directory if it doesn't exist

    try:
        print("Cloning repository...")
        repo_path = clone_repos(args.github_url, destination)  # Clone the GitHub repository

        if not os.path.exists(os.path.join(repo_path, "requirements.txt")):  # Check for requirements.txt
            print("Warning: No `requirements.txt` file found in the project.")

        print("Analyzing libraries...")
        libraries = analyze_project(repo_path)  # Analyze imported libraries
        print(f"Imported Libraries ({len(libraries)}):")
        for lib in sorted(libraries):  # Display unique libraries
            print(f"  - {lib}")

        print("Checking for security issues...")
        vulnerabilities = check_security(libraries)  # Check for vulnerabilities
        if vulnerabilities:
            print("Security Issues Found:")
            for issue in vulnerabilities:
             
                print(f"  - {issue}")
        else:
            print("No security issues found.")

    finally:
        subprocess.run(["rmdir", "/s", "/q", destination], shell=True)  # Clean up cloned repositories
        print("Cleanup completed.")


if __name__ == "__main__":
    main()