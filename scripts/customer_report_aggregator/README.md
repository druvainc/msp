# Product Reporting API Script

## Overview

This python3 script generates a CSV file, containing aggregated records of configured product report for all the customers managed by the MSP.

The details of all available Druva APIs for product reports can be found under platform section in [here](https://developer.druva.com/reference/).

## Prerequisites
Run this command:
- Install python3 on system, if not installed already.
- Install pip3 on system, if not installed already.
- Install dependency modules needed by this sample script:
```commandline
cd scripts/customer_report_aggregator/
pip3 install -r requirements.txt
```
If the above command fails, retry above commands after upgrading the pip with following command:
```commandline
pip3 install --upgrade pip
```

## Configure example aggregator script
Steps to configure this sample product report aggregator script:
- Create client credentials by following steps mentioned [here](https://docs.druva.com/Managed_Service_Center/Administration/Integration_with_Druva_MSP_APIs), skip if already created.
- Update the `config.json` file with the newly generated (or a pre-existing) clientID and clientSecret pair.
- Set the endpoint url of the product report of your choice in `reportURL` field of `config.json`. Endpoint URL of a product report can be found at the top of corresponding API documentation page. See [here](https://developer.druva.com/reference) for a full list of product reports accessible as APIs.
- Update field `reportFilters` to apply required filters.
```
{
    "reportURL" : "<URL of the report to be fetched>",
    "clientID": "<MSP client ID>",
    "clientSecret": "<MSP client secret>",
    "reportFilters": {
        "pageSize": 100,
        "filterBy": [
            {
                "fieldName": "lastUpdatedTime",
                "value": "2023-11-14T00:00:00Z",
                "operator": "GTE"
            }
        ]
    }
}
```

## Generate aggregated report
To generate aggregated report, run the following command:
```commandline
python customer_report_aggregator.py config.json
```
A file in csv format will get created in the current directory and similar logs will be generated on the terminal :
```
python customer_report_aggregator.py config.json
Fetched 7 customers
1 / 7 : Fetching report for 'MSP SE LAB Sandbox'
Successfully fetched all pages of the report for 'MSP SE LAB Sandbox'
2 / 7 : Fetching report for 'Tenant ABC'
Successfully fetched all pages of the report for 'Tenant ABC'
3 / 7 : Fetching report for 'Demo'
Successfully fetched all pages of the report for 'Demo'
4 / 7 : Fetching report for 'Support Lab'
Successfully fetched all pages of the report for 'Support Lab'
5 / 7 : Fetching report for 'ToDelete'
Successfully fetched all pages of the report for 'ToDelete'
6 / 7 : Fetching report for 'Customer 10'
Report not available for customer 'Customer 10'.
7 / 7 : Fetching report for 'Customer 12'
Report not available for customer 'Customer 12'.
Saved aggregated report in 'epAlert_14-12-2023_21-50-21.csv' in current directory
```
