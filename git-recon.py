import os
import git
import re
import json
import subprocess
import tempfile
import shutil
import sys
from colorama import Fore, Style, init

# Initialize colorama
init()

# Collect user input
owner = input("Enter the GitHub owner/organization name: ").strip()
repo = input("Enter the repository name: ").strip()
trivy_path = input("Enter the path to the Trivy binary (leave empty if in PATH): ").strip()

# Default to 'trivy' if no custom path is provided
if not trivy_path:
    trivy_path = "trivy"

# Create a temporary directory
print(f"{Fore.CYAN}Creating a temporary directory for cloning the repository...{Style.RESET_ALL}")
temp_dir = tempfile.mkdtemp()
repo_url = f"https://github.com/{owner}/{repo}.git"
repo_dir = os.path.join(temp_dir, repo)

# Function to clone the repository with error handling
def clone_repo(repo_url, repo_dir):
    try:
        print(f"{Fore.BLUE}Cloning repository from {repo_url} into {repo_dir}...{Style.RESET_ALL}")
        git.Repo.clone_from(repo_url, repo_dir)
        print(f"{Fore.GREEN}Repository cloned successfully.{Style.RESET_ALL}")
    except git.exc.GitError as e:
        print(f"{Fore.RED}Error cloning repository: {e}{Style.RESET_ALL}")
        shutil.rmtree(temp_dir)
        sys.exit(1)

# Function to gather README content and display it
def display_readme(repo_dir):
    readme_files = ["README.md", "README.rst", "README.txt"]
    readme_content = ""

    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            if file in readme_files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        readme_content = f.read()
                    print(f"{Fore.CYAN}Displaying README content from {file_path}...{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{readme_content}{Style.RESET_ALL}")
                    return
                except Exception as e:
                    print(f"{Fore.RED}Error reading README file {file_path}: {e}{Style.RESET_ALL}")

    if not readme_content:
        print(f"{Fore.RED}No README file found in the repository.{Style.RESET_ALL}")

# Function to gather file structure and detect technologies
def gather_intel(repo_dir):
    print(f"{Fore.CYAN}Gathering file structure and detecting technologies...{Style.RESET_ALL}")
    file_structure = []
    tech_used = set()
    code_snippets = []
    config_files_content = []
    tech_patterns = {
        'Swift': r'\.swift$',
        'Markdown': r'\.md$',
        'JSON': r'\.json$',
        'XML': r'\.xml$',
        'YAML': r'\.yml$|\.yaml$',
        'Bash': r'\.sh$',
        'Java': r'\.java$',
        'Kotlin': r'\.kt$|\.kts$',
        'Ruby': r'\.rb$',
        'Proto': r'\.proto$',
        'Gradle': r'\.gradle$|\.gradlew$',
        'Python': r'\.py$',
        'JavaScript': r'\.js$|\.jsx$',
        'TypeScript': r'\.ts$|\.tsx$',
        'Go': r'\.go$',
        'HTML': r'\.html$|\.htm$',
        'CSS': r'\.css$',
        'SCSS': r'\.scss$',
    }

    config_files = ["package.json", "requirements.txt", "Dockerfile", "docker-compose.yml", "Pipfile"]

    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_structure.append(file_path.replace(repo_dir, ""))

            # Check if the file is a configuration file
            if file in config_files:
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        config_files_content.append(f"{file}:\n{f.read()}")
                except Exception as e:
                    print(f"{Fore.RED}Error reading config file {file_path}: {e}{Style.RESET_ALL}")

            for tech, pattern in tech_patterns.items():
                if re.search(pattern, file_path):
                    tech_used.add(tech)

            # Extract code snippets from source files
            if file.endswith(tuple(tech_patterns.keys())):
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        # Extract the first 10 lines as a sample snippet
                        snippet = "\n".join(content.splitlines()[:10])
                        code_snippets.append(snippet)
                except Exception as e:
                    print(f"{Fore.RED}Error reading file {file_path}: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}File structure and technology detection completed.{Style.RESET_ALL}")
    return file_structure, tech_used, code_snippets, config_files_content

# Function to detect vulnerabilities using Trivy with error handling
def detect_vulns_trivy(repo_dir, trivy_path):
    try:
        print(f"{Fore.BLUE}Running Trivy to detect vulnerabilities in {repo_dir}...{Style.RESET_ALL}")
        result = subprocess.run([trivy_path, 'fs', '--format', 'json', '-o', 'trivy_report.json', repo_dir], check=True)
        if result.returncode != 0:
            print(f"{Fore.RED}Error running Trivy{Style.RESET_ALL}")
            shutil.rmtree(temp_dir)
            sys.exit(1)
        with open("trivy_report.json", 'r') as f:
            trivy_report = json.load(f)
        print(f"{Fore.GREEN}Trivy scan completed successfully.{Style.RESET_ALL}")
        return trivy_report
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error executing Trivy: {e}{Style.RESET_ALL}")
        shutil.rmtree(temp_dir)
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error reading Trivy report: {e}{Style.RESET_ALL}")
        shutil.rmtree(temp_dir)
        sys.exit(1)

# Inform user about the steps being performed
print(f"{Fore.CYAN}Starting the repository analysis...{Style.RESET_ALL}")

# Clone the repository
clone_repo(repo_url, repo_dir)

# Display README content
display_readme(repo_dir)

# Gather file structure, technologies used, code snippets, and config files content
file_structure, tech_used, code_snippets, config_files_content = gather_intel(repo_dir)

# Detect vulnerabilities
trivy_report = detect_vulns_trivy(repo_dir, trivy_path)

# Generate and display the report
print(f"{Fore.CYAN}Generating the final report...{Style.RESET_ALL}")
report = {
    "File Structure": file_structure,
    "Technologies Used": list(tech_used),
    "Vulnerabilities": trivy_report
}

print(json.dumps(report, indent=4))

# Display vulnerabilities in a readable format
def display_vulnerabilities(trivy_report):
    vulnerabilities = trivy_report.get("Results", [])
    for result in vulnerabilities:
        target = result.get("Target")
        vulnerabilities_list = result.get("Vulnerabilities", [])
        if vulnerabilities_list:
            print(f"{Fore.RED}\nVulnerabilities in {target}:{Style.RESET_ALL}")
            for vuln in vulnerabilities_list:
                print(f"  - ID: {vuln.get('VulnerabilityID')}")
                print(f"    PkgName: {vuln.get('PkgName')}")
                print(f"    Severity: {vuln.get('Severity')}")
                print(f"    Description: {vuln.get('Description')}")
                print(f"    FixedVersion: {vuln.get('FixedVersion')}")
                print(f"    References: {', '.join(vuln.get('References', []))}\n")

# Display the file structure and technologies used
print(f"{Fore.CYAN}\nFile Structure:{Style.RESET_ALL}")
for file in file_structure:
    print(f"  - {file}")

print(f"{Fore.CYAN}\nTechnologies Used:{Style.RESET_ALL}")
for tech in tech_used:
    print(f"  - {tech}")

print(f"{Fore.CYAN}\nVulnerability Report:{Style.RESET_ALL}")
display_vulnerabilities(trivy_report)

# Cleanup the temporary directory
print(f"{Fore.CYAN}Cleaning up the temporary directory...{Style.RESET_ALL}")
shutil.rmtree(temp_dir)
print(f"{Fore.GREEN}Analysis completed.{Style.RESET_ALL}")
