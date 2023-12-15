"""Fetches report for the customers and saves them in a file"""
import base64
import csv
from datetime import datetime
import json
import sys
import time
import traceback

import requests

CFG_KEY_HOST_NAME = "hostName"
CFG_KEY_CLIENT_ID = "clientID"
CFG_KEY_CLIENT_SECRET = "clientSecret"
CFG_KEY_REPORT_URL = "reportURL"
CFG_KEY_REPORT_FILTERS = "reportFilters"

CONFIG_MAP = None


def init():
    """init() populates client credentials and other configurable parameters from the config file."""
    input_file_name = sys.argv[1].strip()
    input_file = open(input_file_name, 'r', encoding="utf-8")
    raw_details = input_file.read()
    details = json.loads(raw_details)

    config_map = {
        CFG_KEY_CLIENT_ID: details[CFG_KEY_CLIENT_ID],
        CFG_KEY_CLIENT_SECRET: details[CFG_KEY_CLIENT_SECRET],
        CFG_KEY_REPORT_URL: details[CFG_KEY_REPORT_URL],
        CFG_KEY_REPORT_FILTERS: details[CFG_KEY_REPORT_FILTERS],
        CFG_KEY_HOST_NAME: "https://apis.druva.com"
    }

    # to fetch different report change the URL in json file
    input_file.close()
    return config_map


def get_msp_access_token():
    """get_msp_access_token() method fetches MSP access token"""
    url = CONFIG_MAP[CFG_KEY_HOST_NAME] + "/msp/auth/v1/token"
    client_id = CONFIG_MAP[CFG_KEY_CLIENT_ID]
    client_secret = CONFIG_MAP[CFG_KEY_CLIENT_SECRET]
    encoded_secrets = '%s:%s' % (client_id, client_secret)
    encoded_secrets = encoded_secrets.encode("ascii")
    auth_string = base64.b64encode(encoded_secrets).decode("ascii")

    data = {
        "grant_type": "client_credentials"
    }
    headers = {
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic " + auth_string
    }
    response = requests.post(url=url, headers=headers, data=data, timeout=30)
    if response.status_code == 200:
        result = json.loads(response.content)
        token_expiry = time.time() + result["expires_in"]
        return result["access_token"], token_expiry
    else:
        print("Failed to fetch msp access token. Nested error:", response.content)
        raise RuntimeError("Failed to fetch MSP access token")


def get_customer_list(msp_access_token):
    """get_customer_list() method fetches the list of MSP customers"""
    url = CONFIG_MAP[CFG_KEY_HOST_NAME] + "/msp/v2/customers"
    headers = {
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer " + msp_access_token
    }
    page_token = ""
    page_size = 100
    resp = []
    while True:
        query_params = "?pageToken=" + page_token + "&pageSize=" + str(page_size)
        response = requests.get(url=url + query_params, headers=headers, timeout=30)
        if response.status_code != 200:
            print("Failed to fetch customer list ", response.content)
            raise RuntimeError("Failed to fetch customer list.")

        result = json.loads(response.content)
        resp.extend(result["customers"])
        if len(result["nextPageToken"]) == 0:
            break

        page_size = ""
        page_token = result["nextPageToken"]
    return resp


def check_report_availability(customer_access_token):
    headers = {
        'Content-Type': 'application/json',
        'accept': 'application/json',
        'Authorization': 'Bearer ' + customer_access_token
    }

    url = CONFIG_MAP[CFG_KEY_HOST_NAME] + '/platform/reporting/v1/reports'
    response = requests.get(url=url, headers=headers, timeout=30)
    if response.status_code != 200:
        print("Failed to check report availability for customer. Nested error:", response.content)
        raise RuntimeError("Failed to check report availability for customer.")

    resp = json.loads(response.content)
    reports = resp["reports"]
    if reports is None:
        # No reports available for this customer, it is probably a hollow customer.
        return False

    for report in reports:
        report_suffix = "/" + report['reportID']
        if CONFIG_MAP[CFG_KEY_REPORT_URL].endswith(report_suffix):
            return True

    return False


def fetch_customer_report(account_name, customer_access_token, page_token):
    """fetch_customer_report fetches the report with page token, if any"""

    headers = {
        'Content-Type': 'application/json',
        'accept': 'application/json',
        'Authorization': 'Bearer ' + customer_access_token
    }
 
    payload = {
        "filters": CONFIG_MAP[CFG_KEY_REPORT_FILTERS],
        "pageToken": page_token
    }
    data = json.dumps(payload)
    response = requests.post(url=CONFIG_MAP[CFG_KEY_REPORT_URL], headers=headers, data=data, timeout=30)
    if response.status_code != 200:
        raise RuntimeError("Got unwanted response while fetching report for customer", account_name, response.content)

    resp = json.loads(response.content)
    return resp["data"], resp["nextPageToken"]


def fetch_customer_access_token(msp_access_token, account_name, customer_global_id):
    """fetch_customer_access_token() fetches the customer access token, used to fetch customer report"""
    url = CONFIG_MAP[CFG_KEY_HOST_NAME] + "/msp/v2/customers/" + customer_global_id + "/token"
    headers = {
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer " + msp_access_token
    }
    data = {
        "grant_type": "client_credentials"
    }
    response = requests.post(url=url, headers=headers, data=data, timeout=30)
    if response.status_code != 200:
        print("Failed to get access token for customer '{:s}'. Nested error:".format(account_name), response.content)
        return ""

    customer_client_token_resp = json.loads(response.content)
    return customer_client_token_resp["access_token"]


def aggregate_customers_report(customers):
    """aggregate_customers_report() iterates over the list of customers, fetches access token and then the report
    for every customer"""
    # file name format is :  dgRollbackActions_07-12-2023_14-21-07.csv
    # saving a file with report name, report name is fetched from url
    file_prefix = CONFIG_MAP[CFG_KEY_REPORT_URL].split('/')
    if len(file_prefix) <= 1:
        raise RuntimeError("Configuration error, unknown format of API endpoint URL specified.")
    file_prefix = file_prefix[len(file_prefix) - 1]
    file_name = file_prefix + "_" + str(datetime.now().strftime("%d-%m-%Y_%H-%M-%S")) + ".csv"

    output_file = open(file_name, "w", newline='', encoding="utf-8")
    header_field_names = ['accountName']
    csvwriter = csv.writer(output_file, quoting=csv.QUOTE_ALL)
    customer_counter = 1
    msp_access_token = None
    token_expiry = time.time()

    for customer in customers:
        print(customer_counter, "/", len(customers), ": Fetching report for '{:s}'".format(customer["accountName"]))
        customer_counter += 1
        fetched_customer_report = False
        account_name = customer["accountName"]
        try:
            if token_expiry <= time.time() + 30:
                msp_access_token, token_expiry = get_msp_access_token()

            customer_access_token = fetch_customer_access_token(msp_access_token=msp_access_token,
                                                                account_name=account_name,
                                                                customer_global_id=customer["id"])

            if len(customer_access_token) == 0:
                print("Failed to fetch access token for customer '{:s}'. Aggregated report will not have records "
                      "belonging to this customer.".format(account_name))
                continue

            if check_report_availability(customer_access_token=customer_access_token) is False:
                print("Report not available for customer '{:s}'.".format(account_name))
                continue

            next_page_token = ""
            while True:
                resp, next_page_token = fetch_customer_report(account_name=account_name,
                                                              customer_access_token=customer_access_token,
                                                              page_token=next_page_token)
                if resp is None:
                    continue

                for data_row in resp:
                    if len(header_field_names) == 1:
                        for key in data_row.keys():
                            header_field_names.append(key)
                        # writing header for csv file
                        csvwriter.writerow(header_field_names)

                    row = [account_name]
                    for index in range(1, len(header_field_names)):
                        row.append(data_row[header_field_names[index]])
                    # writing data_row in csv file
                    csvwriter.writerow(row)

                if len(resp) > 0:
                    fetched_customer_report = True

                if len(next_page_token) == 0:
                    break
            print("Successfully fetched all pages of the report for '{:s}'".format(account_name))
        except Exception as fault:
            print("Got error while fetching report contents for '{:s}'.".format(account_name), fault)
            traceback.print_exc()
            if fetched_customer_report:
                print("Partially fetched report contents for '{:s}', could not fetch all records".format(account_name))
            else:
                print("Failed to fetch any record for '{:s}'".format(account_name))

    print("Saved aggregated report in '{:s}' in current directory".format(file_name))
    output_file.close()


def main():
    """main function"""
    if len(sys.argv) != 2:
        print("Usage syntax: {:s} <config.json file path>".format(sys.argv[0]))
        return

    # loading data from config file
    global CONFIG_MAP
    CONFIG_MAP = init()

    msp_access_token, _ = get_msp_access_token()
    customers = get_customer_list(msp_access_token=msp_access_token)
    if customers is None:
        print("No customers found, can not generate aggregated report.")
        return

    print("Fetched {:d} customers".format(len(customers)))
    aggregate_customers_report(customers=customers)

    return


main()
