#!/usr/bin/env python3

import gzip
import json
import os
import requests
from datetime import datetime
from typing import Union
from urllib.parse import urljoin


class NVD:
    """NVD(National Vulnerability Database) Class"""

    def __init__(self, download_directory: Union[str] = None):
        if download_directory is not None:
            if os.path.exists(download_directory):
                self.download_directory = download_directory
            else:
                raise FileNotFoundError
        else:
            self.download_directory: str = os.path.dirname(__file__)
        # NVD provides from years of 2002
        self.base_year: int = 2002
        # current year
        self.current_year: str = datetime.now().strftime('%Y')
        # NVD feed
        self.feed: str = 'https://nvd.nist.gov/feeds/json/cve/1.1/'
        # RESTful API
        self.api: str = 'https://services.nvd.nist.gov/rest/json/cve/1.0/'
        # request header
        self.headers: dict = {'Content-Type': 'application/json'}

    def _make_dir(self) -> None:
        """Make Directory"""

        for year in range(self.base_year, int(self.current_year) + 1):
            dir_to_make = os.path.join(
                self.download_directory, f'CVE-{str(year)}')

            if not os.path.isdir(dir_to_make):
                os.mkdir(dir_to_make)

    def download_json_feed(self, start: Union[int] = None,
                           end: Union[int] = None) -> None:
        """NVD JSON feed Download

        :param start: Range (start) year to download (default: 2002)
        :type start: int | None
        :param end: Range (end) year to download (default: current year)
        :type end: int | None
        """

        if (start is None) and (end is None):
            start = self.base_year
            end = int(self.current_year)

        self._make_dir()

        for year in range(start, end + 1):
            gzfile = f'nvdcve-1.1-{year}.json.gz'
            decompress_file = f'nvdcve-1.1-{year}.json'

            json_feed_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/' + gzfile
            response = requests.get(url=json_feed_url, headers=self.headers,
                                    stream=True, allow_redirects=True)

            download_path = os.path.join(self.download_directory, f'CVE-{year}')
            with open(file=os.path.join(download_path, decompress_file),
                      mode='wb') as fp:
                dec_file = gzip.decompress(response.content)
                fp.write(dec_file)

    def extract_single_cve(self, start: Union[int] = None,
                           end: Union[int] = None) -> None:
        """Extract Single CVE file from nvdcve-1.1-{year}.json

        :param start: Range (start) year to split cve (default: 2002)
        :type start: int | None
        :param end: Range (end) year to split cve (default: current year)
        :type end: int | None
        """

        if (start is None) and (end is None):
            start = self.base_year
            end = int(self.current_year)

        for year in range(start, end + 1):
            json_feed_file = os.path.join(self.download_directory,
                                          f'CVE-{year}',
                                          f'nvdcve-1.1-{year}.json')
            with open(file=json_feed_file) as fp:
                vulnerabilities = json.load(fp)
            for vuln in vulnerabilities['CVE_Items']:
                cve = vuln['cve']['CVE_data_meta']['ID']
                with open(os.path.join(self.download_directory, f'CVE-{year}',
                                       f'{cve}.json'), mode='w') as fp:
                    json.dump(vuln, fp, indent=4)

    def search_cve_info(self, cve: str) -> dict:
        """Retrieve specific CVE information"""

        url = urljoin(base=self.api, url=cve, allow_fragments=True)

        return requests.get(url=url).json()
