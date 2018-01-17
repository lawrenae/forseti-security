# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Email utility module."""

from send_email import SMTPEmail
from send_email import SendGridEmail

from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class EmailUtil(object):
    """Utility for sending emails."""

    @staticmethod
    def from_config(pipeline_config):
        """Factory Method to return the right Email sending instance

           Args:
               pipeline_config (dict): The application config object

           Returns:
               Email: The correct instance of Email (SendGrid or SMTP)
        """
        if 'sendgrid_api_key' in pipeline_config:
            return SendGridEmail(pipeline_config['sendgrid_api_key'])

        return SMTPEmail(
            pipeline_config.get('smtp_host'),
            pipeline_config.get('smtp_port', "25"),
            pipeline_config.get('smtp_username', None),
            pipeline_config.get('smtp_password', None)
        )

    def __init__(self):
        raise NotImplementedError("Don't instantiate this class")
