# File: blockshield_connector.py
#
# Copyright (c) 2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from blockshield_consts import (
    BLOCKSHIELD_API_BULK_DOMAINS,
    BLOCKSHIELD_API_BULK_IPS,
    BLOCKSHIELD_API_BULK_URLS,
    BLOCKSHIELD_API_IPINFO,
    BLOCKSHIELD_CONNECTIVITY_ENDPOINT,
    BLOCKSHIELD_ERR_CONNECTIVITY_TEST,
    BLOCKSHIELD_SUCC_CONNECTIVITY_TEST,
)



class BlockshieldConnector(BaseConnector):
    """
    Blockshield connector class that serves as a starting point for new connectors.
    """

    def __init__(self):
        super().__init__()
        self._base_url = None
        self._api_key = None
        self._verify = False
        self._timeout = 30

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, json=None, method="get"):
        """
        Helper function to make REST calls for the connector.
        """
        try:
            url = f"{self._base_url}{endpoint}"
            self.debug_print(f"Making REST call to: {url}")

            request_func = getattr(requests, method.lower())

            response = request_func(url, json=json, data=data, headers=headers, params=params, verify=self._verify)

            # Add debug data
            if hasattr(action_result, "add_debug_data"):
                action_result.add_debug_data({"r_status_code": response.status_code})
                action_result.add_debug_data({"r_text": response.text})
                action_result.add_debug_data({"r_headers": response.headers})

            # Process response
            if 200 <= response.status_code < 300:
                try:
                    if response.text:
                        return phantom.APP_SUCCESS, response.json()
                    return phantom.APP_SUCCESS, {}
                except ValueError:
                    return phantom.APP_SUCCESS, response.text

            # Error handling
            error_message = f"Error from server. Status Code: {response.status_code}"
            if response.text:
                try:
                    resp_json = response.json()
                    error_message = f"Error from server. Status Code: {response.status_code}. Error: {resp_json.get('error', 'Unknown error')}"
                except ValueError:
                    error_message = f"Error from server. Status Code: {response.status_code}. Error: {response.text}"

            return action_result.set_status(phantom.APP_ERROR, error_message), None

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Error making REST call: {e!s}"), None

    def _handle_test_connectivity(self, param):
        """
        Validate the asset configuration for connectivity using supplied credentials.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to instance...")

        # Example test connectivity code
        endpoint = BLOCKSHIELD_CONNECTIVITY_ENDPOINT
        headers = {"Authorization": f"Bearer {self._api_key}"}

        ret_val, _ = self._make_rest_call(endpoint, action_result, headers=headers)

        if phantom.is_fail(ret_val):
            self.save_progress(BLOCKSHIELD_ERR_CONNECTIVITY_TEST)
            return action_result.get_status()

        self.save_progress(BLOCKSHIELD_SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    def initialize(self):
        """
        Initialize the connector.
        """
        self.debug_print("Initializing connector")
        config = self.get_config()

        # Get configuration parameters
        self._base_url = config.get("base_url")
        self._api_key = config.get("api_key")
        self._timeout = config.get("timeout", 30)
        self._verify = config.get("verify_server_cert", False)

        if not self._base_url or not self._api_key:
            self.save_progress("Missing required configuration parameters")
            return phantom.APP_ERROR

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self._session.verify = config.get("verify_ssl", True)

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """
        Dispatcher for actions.
        """
        self.debug_print("action_id ", self.get_action_identifier())

        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "ipinfo": self._handle_ipinfo,
            "bulk_domains": self._handle_bulk_domains,
            "bulk_ips": self._handle_bulk_ips,
            "bulk_urls": self._handle_bulk_urls,
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping:
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    # -------------------------------------------------------------------------
    # IP Info Action
    # -------------------------------------------------------------------------

    def _handle_ipinfo(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param.get("ip")
        if not ip:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameter: 'ip'")

        ret_val, response = self._make_rest_call(f"{BLOCKSHIELD_API_IPINFO}/{ip}", action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"ip": ip})

        return action_result.set_status(phantom.APP_SUCCESS, f"Successfully retrieved info for IP {ip}")

    # -------------------------------------------------------------------------
    # Bulk Actions
    # -------------------------------------------------------------------------

    def _handle_bulk_domains(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        domains = [d.strip() for d in param.get("domains", "").split(",") if d.strip()]
        source = param.get("source")
        description = param.get("description")

        if not domains or not source:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameters: 'domains' or 'source'")

        data = {"domains": domains, "source": source, "description": description}

        ret_val, response = self._make_rest_call(BLOCKSHIELD_API_BULK_DOMAINS, action_result, method="post", data=data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"domains_added": len(domains)})

        return action_result.set_status(phantom.APP_SUCCESS, f"Successfully added {len(domains)} domains")

    def _handle_bulk_ips(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ips = [ip.strip() for ip in param.get("ips", "").split(",") if ip.strip()]
        source = param.get("source")
        subnet = param.get("subnet", 32)
        reported_by = param.get("reported_by", "")
        description = param.get("description")

        if not ips or not source:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameters: 'ips' or 'source'")

        data = {"ips": ips, "source": source, "subnet": subnet, "reported_by": reported_by, "description": description}

        ret_val, response = self._make_rest_call(BLOCKSHIELD_API_BULK_IPS, action_result, method="post", data=data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"ips_added": len(ips)})

        return action_result.set_status(phantom.APP_SUCCESS, f"Successfully added {len(ips)} IPs")

    def _handle_bulk_urls(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        urls = [u.strip() for u in param.get("urls", "").split(",") if u.strip()]
        source = param.get("source")
        description = param.get("description")

        if not urls or not source:
            return action_result.set_status(phantom.APP_ERROR, "Missing required parameters: 'urls' or 'source'")

        data = {"urls": urls, "source": source, "description": description}

        ret_val, response = self._make_rest_call(BLOCKSHIELD_API_BULK_URLS, action_result, method="post", data=data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({"urls_added": len(urls)})

        return action_result.set_status(phantom.APP_SUCCESS, f"Successfully added {len(urls)} URLs")

if __name__ == "__main__":
    import sys

    import pudb

    pudb.set_trace()

    connector = BlockshieldConnector()
    connector.print_progress_message = True

    sys.exit(0)
