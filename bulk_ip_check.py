#==============================================
# Packages to install are : getpass, datetime, requests, json, xlsxwriter, re, country_converter, pyfiglet
# Extracts IP addresses from .csv and .txt files
# IPs will be checked with AbuseIPDB API and get exported to an Excel file
# Total of 5000 IP can be scanned using the tool
#==============================================
from getpass import getpass
from datetime import datetime
import requests
import json
import xlsxwriter
import re
import os
import country_converter as coco
import pyfiglet


print('**********************************************************************************')
print('**********************************************************************************')

ascii_art = pyfiglet.figlet_format("BULK-IP-CHECK")
print(ascii_art)
print(" " * 70 + "\033[3mBy Subhajit.\033[0m")

print('**********************************************************************************')
print('**********************************************************************************')



# Add results from API response to lists
def update_result_list(response_json):
    result_list.append([
        str(response_json["data"]["ipAddress"]),
        str(response_json["data"]["isTor"]),
        str(response_json["data"]["isWhitelisted"]),
        str(response_json["data"]["abuseConfidenceScore"]),
        str(response_json["data"]["totalReports"]),
        str(response_json["data"]["countryCode"]),
        coco.CountryConverter().convert(str(response_json["data"]["countryCode"]), to='name_short'),
        str(response_json["data"]["isp"]),
        str(response_json["data"]["lastReportedAt"])
    ])


# Print result on console
def print_results(response_json):
    print("IP: " + str(response_json["data"]["ipAddress"]))
    print("Is Tor: " + str(response_json["data"]["isTor"]))
    print("Is Whitelisted: " + str(response_json["data"]["isWhitelisted"]))
    print("Malicious: " + str(response_json["data"]["abuseConfidenceScore"]) + "%")
    print("Number of reports: " + str(response_json["data"]["totalReports"]))
    print("Country: " + str(response_json["data"]["countryCode"]))
    print("Country Name: " + coco.CountryConverter().convert(str(response_json["data"]["countryCode"]), to='name_short'))
    print("ISP: " + str(response_json["data"]["isp"]))
    print("Last reported: " + str(response_json["data"]["lastReportedAt"]))


# Import result to Excel
def write_to_excel():
    now = datetime.now()
    dt_string = now.strftime("%d%m%Y-%H%M%S")
    filename = 'abuseipdb_export-' + dt_string + '.xlsx'
    # Create an new Excel file and add a worksheet.
    workbook = xlsxwriter.Workbook(os.path.join(path, filename))  # Location for file export
    worksheet = workbook.add_worksheet()  # Insert sheet
    bold = workbook.add_format({'bold': True})  # Activate bold font
    # Set column width
    worksheet.set_column('A:A', 15)
    worksheet.set_column('B:B', 20)
    worksheet.set_column('C:C', 20)
    worksheet.set_column('D:D', 25)
    worksheet.set_column('E:E', 20)
    worksheet.set_column('F:F', 10)
    worksheet.set_column('G:G', 35)
    worksheet.set_column('H:H', 30)
    worksheet.set_column('I:I', 30)

    # Create titel row
    worksheet.write('A1', 'IP', bold)
    worksheet.write('B1', 'Is Tor', bold)
    worksheet.write('C1', 'Is Whitelisted', bold)
    worksheet.write('D1', 'Abuse confidence in %', bold)
    worksheet.write('E1', 'Number of reports', bold)
    worksheet.write('F1', 'Country Code', bold)
    worksheet.write('G1', 'Country Name', bold)
    worksheet.write('H1', 'ISP', bold)
    worksheet.write('I1', 'Last reported', bold)

    # write results into Excel
    for ip in range(len(result_list)):
        worksheet.write('A'+str(ip+2), result_list[ip][0]),
        worksheet.write('B'+str(ip+2), result_list[ip][1]),
        worksheet.write('C'+str(ip+2), result_list[ip][2]),
        worksheet.write('D'+str(ip+2), result_list[ip][3]),
        worksheet.write('E'+str(ip+2), result_list[ip][4]),
        worksheet.write('F'+str(ip+2), result_list[ip][5]),
        worksheet.write('G'+str(ip+2), result_list[ip][6]),
        worksheet.write('H'+str(ip+2), result_list[ip][7]),
        worksheet.write('I'+str(ip+2), result_list[ip][8])


    print(f"File saved at: \n{os.path.join(path, filename)}")
    workbook.close()


# Send IPs to API
def do_request(ips, abuseipdb_apikey):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_apikey
    }
    # Iterate through list of IPs and send to API
    for ip in ips:
        querystring = {
            'ipAddress': ip,
#            'maxAgeInDays': '90'#Gives the report based on last 90 days. We can use a value according to us
        }
        response = requests.get(url=url, headers=headers, params=querystring)
        response_json = json.loads(response.text)
        update_result_list(response_json)  # Add results to list


def extract_ips_from_file(file):
    # Open and read input file
    with open(file) as f:
        fstring = f.readlines()
    
    # Declare Regex pattern
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    total_IPs = len(fstring) #Stores the total number of IPs
    print("Total Ip's in file: " + str(total_IPs))
    limit = 1000 #This is the max limit for a single API
    start = 0
    end = 0
    ips = []
    apis = ["411375928c11b48731f670c9d3b29711d9366de59b823cd5fbc1e3e7869a68402d8b30cbcc39e8ce","5860af0f10019d0f5a94d0b613b0fd9ec6f5db31f9e17f4b25bc1b3261498317499c30133805b3a9"]

    while(total_IPs>0):
        if total_IPs < limit:
            start = start
            end = end + total_IPs
        else:
            start = start
            end = end + limit
        # Extract IPs
        for line in range(start, end):
            element = fstring[line]
            ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', element)
            if ip:
                for i in ip:
                    ips.append(pattern.search(element)[0])

        do_request(ips, apis[(start//limit)])
        write_to_excel()
        ips = []
        start = start + limit
        total_IPs = total_IPs - limit


if __name__ == "__main__":
    try:
        file = input("Please enter proper path to input file: \n").encode('unicode-escape').decode()
        path = os.path.dirname(os.path.abspath(file))
        ips = []
        result_list = []
        extract_ips_from_file(file)
    except FileNotFoundError:
        print("Error: The file does not exist. Please check the file name and try again.")
   
    
