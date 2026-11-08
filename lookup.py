import json
import requests
import os
import matplotlib.pyplot as plt
from collections import Counter

## Lexie

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', 'YOUR_API_KEY_HERE')
VT_API_KEY = os.environ.get('VT_API_KEY', 'YOUR_API_KEY_HERE')


def abusedb(ip):
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)

    # making dictionaries for the different values
    results[name]["Ip"][ip]["ipAddress"] = {}
    results[name]["Ip"][ip]["ipVersion"] = {}
    results[name]["Ip"][ip]["countryCode"] = {}
    results[name]["Ip"][ip]["isp"] = {}
    results[name]["Ip"][ip]["domain"] = {}
    results[name]["Ip"][ip]["usageType"] = {}
    results[name]["Ip"][ip]["abuseConfidenceScore"] = {}
    results[name]["Ip"][ip]["totalReports"] = {}

    # adding values to a tuple and looping through it for when a value is found to be the key
    result_values = ("ipAddress", "ipVersion", "countryCode", "isp", "domain", "usageType", "totalReports",
                     "abuseConfidenceScore")
    for key, value in decodedResponse["data"].items():
        if key in result_values:
            results[name]["Ip"][ip][key] = value


with open("ps_output.json", "r", encoding="utf-16") as f:  # powershell gives utf-16 files
    data = json.load(f)

    # putting the 3 categories in seperate variables using .get
    processes = data.get("processes")
    hashes = data.get("hashes")
    network = data.get("network")
    ip_addresses = [] # used for report later
    # making a new json file
    results = {}

    for p in processes:
        # getting information for each process if present
        name = p.get("Name")
        path = p.get("Path")
        id = p.get("Id")
        main = p.get("MainModule") or {}
        module = main.get("ModuleName")
        file_ver_info = main.get("FileVersionInfo") or {}
        product = file_ver_info.get("ProductName")

        if name in results:
            # append if name and path are the same
            if results[name]["Path"] == path:
                results[name]["Id"].add(id)
                results[name]["ModuleName"].add(module)
                results[name]["ProductName"].add(product)

            # if path and name not match
            if results[name]["Path"] != path:
                counter = 1
                new_name = f"{name}{counter}"  # add a number to the name to make it unique
                # looping in case name still isn't unique
                while new_name not in results:
                    # if still not unique, add one to the counter and add the number to it
                    if new_name in results:
                        counter += 1
                        new_name = f"{name}{counter}"

                    # if name is unique now, adding a new dictionary
                    if new_name not in results:
                        results[new_name] = {}
                        # appending it with information
                        results[name]["Name"] = name
                        results[name]["Path"] = path
                        results[name]["Id"] = {id}
                        results[name]["ModuleName"] = {module}
                        results[name]["ProductName"] = {product}

        if name not in results:
            # making nested dictionary
            results[name] = {}
            # appending it with information
            results[name]["Name"] = name
            results[name]["Path"] = path
            results[name]["Id"] = {id}
            results[name]["ModuleName"] = {module}
            results[name]["ProductName"] = {product}

    # looping through names to add hashes and remote ip addresses
    for name in results:
        for h in hashes:
            path = h.get("Path")
            hash = h.get("Hash")
            # adding hashes
            if results[name]["Path"] == path:
                if "Hash" in results[name]:
                    results[name]["Hash"].add(hash)
                else:
                    results[name]["Hash"] = {hash}

        # adding remote IP addresses
        for n in network:
            address = n.get("RemoteAddress")
            id = n.get("OwningProcess")

            if id in results[name]["Id"]:
                ip_addresses.append(address)
                if "Ip" in results[name]:
                    results[name]["Ip"].add(address)
                else:
                    results[name]["Ip"] = {address}

for name in results:
    # converting sets to lists if there are more than 1 item in it
    for key, value in results[name].items():
        if isinstance(value, set):
            if len(value) > 1:
                results[name][key] = list(value)
            else:
                results[name][key] = next(iter(value))

for name in results:
    # getting all names with ip's in it
    ip = results[name].get("Ip")
    if "Ip" in results[name]:
        # if it is a list, convert every ip to its seperate dictionary
        if isinstance(ip, list):
            results[name]["Ip"] = {i: {} for i in ip}

            # query every ip seperately
            for i in ip:
                abusedb(i)
        else:
            results[name]["Ip"] = {ip: {}}
            abusedb(ip)

    hash = results[name].get("Hash")
    if "Hash" in results[name]:
        results[name]["Hash"] = {}
        headers = {
            'x-apikey': VT_API_KEY
        }
        url = 'https://www.virustotal.com/api/v3/files/'
        response = requests.get(
            f"{url}{hash.strip()}",
            headers=headers,
            timeout=10
        )
        reply = response.json()

        # variables that will be used in loops
        malicious = 0
        suspicious = 0
        undetected = 0
        names = []
        malicious_engines = []

        # collecting engine names that detected hash as malicious
        for company in reply["data"]["attributes"]["last_analysis_results"]:
            engine = ""
            for key, value in reply["data"]["attributes"]["last_analysis_results"][company].items():

                # storing engine game in variable engine
                if key == "engine_name":
                    engine = value
                # if category is malicious, appending it
                if key == "category":
                    if value == "malicious":
                        malicious_engines.append(engine)

        # malicious, suspicious and undetected overview
        for key, value in reply["data"]["attributes"]["last_analysis_stats"].items():
            if key == "malicious":
                malicious += value
            if key == "suspicious":
                suspicious += value
            if key == "undetected":
                undetected += value

        # storing result in variables for later use
        detections = malicious + suspicious + undetected
        score = f"{malicious - suspicious}/{detections}"

        # finding all names vt knows this hash as
        for item in reply["data"]["attributes"]["names"]:
            names.append(item)

        # adding values to dictionary
        results[name]["Hash"]["Hash"] = hash
        results[name]["Hash"]["Names"] = names
        results[name]["Hash"]["Malicious"] = malicious
        results[name]["Hash"]["Detections"] = detections
        results[name]["Hash"]["Score"] = score

## Adam Lamont

def visualize_results(data, label1, label2):
    """Uses matplotlib to save frequency of inputted values to a .png file.
    data: The data you want to graph.
    label1: X-Axis label and the name of the file.
    label2: Y-Axis label.
    """
    try:
        data = dict(Counter(data)) # Dict of data : count.

       # Trying to get it to output 3840x2160 to prevent sizing issues.
        plt.figure(figsize=(38.4, 21.6))

        # Using matplotlib to produce bar chart.
        plt.bar(data.keys(), data.values())
        plt.xlabel(label1)
        plt.ylabel(label2)

        # Saving image
        plt.savefig(f"{label1}.png", dpi=100) # DPI is needed to compliment .figure.

    except Exception as e:
        print("An error occured:",e) # Printing error


def create_report(processes,ip_addresses):
    """Creates report in CLI format.
    processes: Dict of processes checked and their hash
    ips: List of ips checked (use one from previous analysing data function.
     """
    print("# Processes and Connections Report:")
    print("## Process Analysis\n")

    # Printing data about processes
    for process_data in processes.values():
        # Separate data for hashes as its dict in a dict.
        hashes = process_data.get("Hash", {})  # Extracting dict from dict.

        # Printing relevant information about each process
        print(f"### Process: {process_data.get('Name')}\n")  # Naming on separate line.
        print(f"Path: {process_data.get('Path')}\nPID: {process_data.get('Id')}\nHash: {hashes.get('Hash')}\n#### VirusTotal Analysis:\nVT Score: {hashes.get('Score')}\nAV Results: (Checked by {hashes.get('Detections')} engines, {hashes.get('Malicious')} flagged it as malicious.)")
        print("---")  # New line for formatting.
        
        # Printing network connections of addresses
        if "Ip" in process_data:  # Finding IP addresses in data.
            print("#### Remote Network Connections:")
            for ip_address, data in process_data["Ip"].items():  # Looping through address values
                # Printing relevant information about ip address
                print(f"IP: {ip_address}")
                print(f"Country: {data.get('countryCode')}\nUsage: {data.get('usageType')}\nAbuseIPDB Confidence Score: {data.get('abuseConfidenceScore')}")
                print("---")

    # Printing data about IP addresses
    print("## IP Analysis\n")
    visualize_results(ip_addresses, "IP Addresses", "Frequency")  # Saving to graph which user can view.

    # Printing count of IP Addresses in list.
    for address, frequency in (Counter(ip_addresses).items()):
        print(f"IP:{address} Frequency: {frequency}.")


create_report(results,ip_addresses)
