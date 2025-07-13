"""
print_infos.py

This module provides utilities to count commits in a JSON file, count vulnerabilities in the data directory,
and execute the final analysis steps including filtering metrics and reporting results.
"""

import logging
import os
import ujson as json
import glob
import modules.calculate_results

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Thresholds for filtering metrics
thresholds = {
    # "lines of code": -1,
    # "cyclomatic complexity": -1,
    # "number of loops": -1,
    # "number of nested loops": -1,
    # "max nesting loop depth": -1,
    "number of parameter variables": -1,
    # "number of callee parameter variables": -1,
    # "number of pointer arithmetic": -1,
    # "number of variables involved in pointer arithmetic": -1,
    # "max pointer arithmetic variable is involved in": -1,
    # "number of nested control structures": -1,
    # "maximum nesting level of control structures": -1,
    # "maximum of control dependent control structures": -1,
    # "maximum of data dependent control structures": -1,
    # "number of if structures without else": -1,
    # "number of variables involved in control predicates": -1
}

def count_commits_in_json(json_file_path):
    """
    Count the total number of commits across all projects in the JSON file.

    Args:
        json_file_path (str): Path to the JSON file containing project commit lists.

    Returns:
        int: Total number of commits found. Returns 0 on error.
    """
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        total_commits = 0
        projects_with_commits = 0
        
        for project in data:
            if 'commits' in project and isinstance(project['commits'], list):
                commit_count = len(project['commits'])
                total_commits += commit_count
                if commit_count > 0:
                    projects_with_commits += 1
        
        # logging.info(f"Total projects in JSON: {len(data)}")
        # logging.info(f"Projects with commits: {projects_with_commits}")
        # logging.info(f"Projects without commits: {len(data) - projects_with_commits}")
        
        return total_commits
        
    except FileNotFoundError:
        logging.error(f"JSON file not found: {json_file_path}")
        return 0
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON file: {e}")
        return 0
    except Exception as e:
        logging.error(f"Error reading JSON file: {e}")
        return 0

def count_vulns_in_directory():
    """
    Count all vulnerability entries across all JSON files in the data/vulns directory.

    Args:
        None

    Returns:
        int: Total number of vulnerabilities found. Returns 0 on error.
    """
    try:
        vulns_dir = os.path.join(os.getcwd(), "data", "vulns")
        
        if not os.path.exists(vulns_dir):
            logging.error(f"Vulns directory not found: {vulns_dir}")
            return 0
        
        total_vulns = 0
        file_count = 0
        project_details = {}
        
        # Iterate through all JSON files in the vulns directory
        for json_file in glob.glob(os.path.join(vulns_dir, "*.json")):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    vuln_data = json.load(f)
                
                # Count entries in this file
                if isinstance(vuln_data, list):
                    vuln_count = len(vuln_data)
                    total_vulns += vuln_count
                    file_count += 1
                    
                    # Store details for each project
                    project_name = os.path.basename(json_file).replace('.json', '')
                    project_details[project_name] = vuln_count
                    
                    # logging.info(f"Project {project_name}: {vuln_count} vulnerabilities")
                else:
                    logging.warning(f"Unexpected data format in {json_file} - expected list")
                    
            except json.JSONDecodeError as e:
                logging.error(f"Error parsing JSON file {json_file}: {e}")
                continue
            except Exception as e:
                logging.error(f"Error reading file {json_file}: {e}")
                continue
        
        # if project_details:
        #     logging.info(f"Average vulnerabilities per project: {total_vulns / file_count:.2f}")
        #     max_project = max(project_details, key=project_details.get)
        #     min_project = min(project_details, key=project_details.get)
        #     logging.info(f"Project with most vulns: {max_project} ({project_details[max_project]})")
        #     logging.info(f"Project with least vulns: {min_project} ({project_details[min_project]})")
        
        return total_vulns
        
    except Exception as e:
        logging.error(f"Error counting vulnerabilities: {e}")
        return 0

def main():
    """
    Main script to report counts of commits, vulnerabilities, and execute analysis.

    Args:
        None

    Returns:
        None
    """
    # Count commits in the JSON file
    print("="*50)
    json_file_path = os.path.join(os.getcwd(), "data", "general", "vulns_projects_with_commits.json")
    total_commits = count_commits_in_json(json_file_path)
    print(f"Total number of commits found: {total_commits}")
    print("="*50)
    # Count vulnerabilities in the directory

    total_vulns = count_vulns_in_directory()
    print(f"Total number of vulnerabilities found: {total_vulns}")
    print("="*50)

    # Comment out the parts that require other directories
    projects = []
    base_dir = os.path.join(os.getcwd(), "repositories", "OSS-Projects")
    for entry in os.listdir(base_dir):
        projects.append(os.path.join(base_dir, entry))
    print("Total number of cloned projects: ", len(projects))
    print("="*50)

    # try:
    #     print("Starting commit count analysis...")
    #     modules.calculate_results.separate_and_filter_calculated_metrics(thresholds)
    #     modules.calculate_results.check_if_function_in_vulns()
    #     modules.calculate_results.calculate_infos()
    #     print("Analysis completed successfully!")
    #     print("="*50)

    # except Exception as e:
    #     logging.error(f"Error during analysis: {e}")
    #     raise

if __name__ == "__main__":
    main()