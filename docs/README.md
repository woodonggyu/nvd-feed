## NVD (National Vulnerbility Database) Usage

* [Guidelines](#guidelines)
* [Functions](#functions)

## Guidelines

This document provides guidelines and examples for NVD APIs. 

This document borrows heavily from:
- [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) 
- Attached (Title : Automation Support for CVE Retrieve.pdf)

## Functions

Before using this module, You must set variable of \`download_directory\`.

<br>

### Download JSON Feeds

| Parameter | Type | Description |
| :--- | :--- | :--- |
| start | `int \| None` | **Optional**. Range (start) year to download (default: 2002) |
| end | `int \| None` | **Optional**. Range (end) year to download (default: current year) |

<br>

### Extract single CVE files

| Parameter | Type | Description |
| :--- | :--- | :--- |
| start | `int \| None` | **Optional**. Range (start) year to download (default: 2002) |
| end | `int \| None` | **Optional**. Range (end) year to download (default: current year) |  

<br>

### Search CVE Information

| Parameter | Type | Description |
| :--- | :--- | :--- |
| cve | `str` | **Required**. Search to CVE number |

