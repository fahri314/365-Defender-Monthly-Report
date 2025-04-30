# 365 Defender Monthly Report

- This tool utilizes incident and device data from Microsoft 365 Defender to assist in report writing.
- It presents the results in a temporary Excel window on separate worksheets, formatted as tables for easy copying into presentation tools such as PowerPoint.
- It provides the option to review True Positive events within the report date range as tabs opened in the browser.
- I developed this project to automate my own workflows. If you have to do such boring tasks too, feel free to customize and use it for your own needs.
- The tool automatically calculates the date range for the previous month based on the day the report is generated, and provides the following data:
  - Report date range
  - Total number of devices
  - Total incident
  - OS Type distribution
  - OS distribution
  - Resolve distribution
  - Severity distribution
  - High severity resolve distribution
  - True positive events table:
  - Incident ID, Last activity, Severity, Incident Name, Classification, Impacted Assets
  - Analyst comments
  - IOC Counts

## Config File

Before running the script, you must modify the values in the config file.

- Supports multiple tenants and offers options at startup.
- If you are using WSL environment check default `excel_path_on_wsl` value is correct.
- Exclusion of e-mail alerts.
- Exclusion of Benign Positive alerts.
- Exclusion of alerts with incident title according to the given keyword list.

`sccauth`, `XSRF-TOKEN`, `ai_session`, `s.SessID` and `SSR` values ​​are automatically calculated from the entered cookie value.

## Obtaining Cookie from Microsoft 365 Defender

You can obtain this cookie data from the network section of your browser while logged in to the session at the address below. You can update cookie value at config file.

<https://security.microsoft.com/incidents?tid=your_tenant_id>

## Dependencies

```bash
python3 -m pip install requests
python3 -m pip install openpyxl
```

### WSLview Installation

This project uses the `wslview` package to open URLs when running in a Windows Subsystem for Linux (WSL) environment. If you are using WSL, you need to install the `wslview` package. If you are running on a real Linux environment or Windows, you do not need to install this package.

In a WSL environment:

```bash
sudo apt update
sudo apt install wslu
```

## Request Limitations

- Maximum page size is:
  - incident: 100
  - Device: 200
- Rate limits:
  - 50 requests per minute
  - 1500 requests per hour
