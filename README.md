# Git Recon

`git-recon.py` is a Python script designed to analyze GitHub repositories for bug bounty purposes. The script clones a specified GitHub repository, displays its README content, detects technologies used within the repository, and checks for vulnerabilities using Trivy.

## Features

- Clones a specified GitHub repository.
- Displays the README content from the repository.
- Gathers information on the file structure and technologies used.
- Detects vulnerabilities in the repository using Trivy.
- Generates a comprehensive report including the file structure, technologies used, and detected vulnerabilities.

## Requirements

- Python 3.6+
- Git
- Trivy
- OpenAI API key (optional, but included for potential future features)

## Installation

1. **Clone this repository**:
    ```bash
    git clone https://github.com/your-username/git-recon.git
    cd git-recon
    ```

2. **Install required Python packages**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Install Trivy**:
    Follow the instructions for your operating system from the [Trivy GitHub page](https://github.com/aquasecurity/trivy).

4. **Set up OpenAI API key (optional)**:
    Add the following line to your `.bashrc` or `.zshrc` file (depending on your shell), replacing `"your_openai_api_key_here"` with your actual API key:
    ```bash
    export OPENAI_API_KEY="your_openai_api_key_here"
    ```
    Then, run:
    ```bash
    source ~/.bashrc  # for bash shell
    source ~/.zshrc   # for zsh shell
    ```

## Usage

Run the script and follow the prompts to enter the GitHub owner/organization name, repository name, and the path to the Trivy binary (if not in PATH):

```bash
python3 git-recon.py
