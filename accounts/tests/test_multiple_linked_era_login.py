"""

Copyright 2016, Institute for Systems Biology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import csv
import logging
from StringIO import StringIO

from django.test import TestCase

from django.contrib.auth.models import User
from accounts.models import AuthorizedDataset, NIH_User, GoogleProject, ServiceAccount, UserAuthorizedDatasets
from tasks.nih_whitelist_processor.utils import NIHWhitelist, DatasetToACLMapping
from tasks.nih_whitelist_processor.django_utils import AccessControlUpdater
from tasks.tests.data_generators import create_csv_file_object

logging.basicConfig(
    level=logging.INFO
)


def get_database_alias():
    return 'default'


class TestNoLinkedNihUser(TestCase):
    def setUp(self):
        test_dataset_mapping = {
            'phs000123': {
                'name': 'This is a study',
                'parent_study': 'phs000111',
                'acl_group': 'acl-phs000123'
            },
            'phs000456': {
                'name': 'Another study',
                'parent_study': 'phs000444',
                'acl_group': 'acl-phs000456'
            }
        }

        self.dataset_acl_mapping = DatasetToACLMapping(test_dataset_mapping)

        self.auth_user = User(first_name='Test', last_name='User', username='test_user', email='test@email.com')
        self.auth_user.save()

        self.nih_user_1 = NIH_User(user=self.auth_user,
                                   NIH_username='USERNAME1',
                                   NIH_assertion='012345689',
                                   dbGaP_authorized=True,
                                   active=True,
                                   linked=False)

        self.nih_user_1.save()

        self.auth_dataset = AuthorizedDataset(name="dataset1", whitelist_id='phs000123', acl_google_group='test_acl')
        self.auth_dataset.save()

        self.project = GoogleProject(project_name="project1",
                                     project_id="123",
                                     big_query_dataset="bq_dataset1")
        self.project.save()
        self.project.user.add(self.auth_user)

        self.account = ServiceAccount(google_project=self.project, service_account="abc", authorized_dataset=self.auth_dataset)
        self.account.save()

    def test_no_linked_nih_user(self):
        """
        Test that no UserAuthorizedDataset objects are to be created, as the only matching NIH_User object
        (nih_user_1) is not linked.
        """
        test_csv_data = [
            ['Test User', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        whitelist = NIHWhitelist.from_stream(create_csv_file_object(test_csv_data, include_header=True))
        dsu = AccessControlUpdater(whitelist, database_alias='default')
        result = dsu.process()

        self.assertEquals(len(result.skipped_era_logins), 1)
        self.assertEquals(len(result.user_auth_dataset_update_result), 0)

        # The service account should not be removed
        self.assertEquals(result.service_account_remove_set, set([]))

    def test_one_linked_nih_user(self):
        """
        Test that one UserAuthorizedDataset object is created, as a linked NIH_User object exists.
        """
        self.auth_user_2 = User(first_name='Test', last_name='User', username='test_user_2', email='test2@email.com')
        self.auth_user_2.save()

        self.nih_user_2 = NIH_User(user=self.auth_user_2,
                                   NIH_username='USERNAME1',
                                   NIH_assertion='012345689',
                                   dbGaP_authorized=True,
                                   active=True,
                                   linked=True)

        self.nih_user_2.save()

        test_csv_data = [
            ['Test User', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        whitelist = NIHWhitelist.from_stream(create_csv_file_object(test_csv_data, include_header=True))
        dsu = AccessControlUpdater(whitelist, database_alias='default')
        result = dsu.process()

        self.assertEquals(len(result.skipped_era_logins), 0)
        self.assertEquals(result.user_auth_dataset_update_result[0].added_dataset_ids, set(['phs000123']))
        self.assertEquals(result.user_auth_dataset_update_result[0].revoked_dataset_ids, set([]))

        # The service account should not be removed
        self.assertEquals(result.service_account_remove_set, set([]))

    def test_multiple_linked_nih_users(self):
        """
        Test that no UserAuthorizedDataset objects are to be created, as the only matching NIH_User object
        (nih_user_1) is not linked.
        """
        self.auth_user_2 = User(first_name='Test', last_name='User', username='test_user_2', email='test2@email.com')
        self.auth_user_2.save()

        self.nih_user_2 = NIH_User(user=self.auth_user,
                                   NIH_username='USERNAME1',
                                   NIH_assertion='012345689',
                                   dbGaP_authorized=True,
                                   active=True,
                                   linked=True)

        self.nih_user_2.save()

        self.auth_user_3 = User(first_name='Test', last_name='User', username='test_user_3', email='test3@email.com')
        self.auth_user_3.save()

        self.nih_user_3 = NIH_User(user=self.auth_user,
                                   NIH_username='USERNAME1',
                                   NIH_assertion='012345689',
                                   dbGaP_authorized=True,
                                   active=True,
                                   linked=True)

        self.nih_user_3.save()

        test_csv_data = [
            ['Test User', 'USERNAME1', 'eRA', 'PI', 'username@fake.com', '555-555-5555', 'active', 'phs000123.v1.p1.c1',
             'General Research Use', '2013-01-01 12:34:56.789', '2014-06-01 16:00:00.100', '2017-06-11 00:00:00.000', '']
        ]

        whitelist = NIHWhitelist.from_stream(create_csv_file_object(test_csv_data, include_header=True))
        dsu = AccessControlUpdater(whitelist, database_alias='default')
        result = dsu.process()

        # skipped_era_logins will be 1 if multiple linked NIH_Users with same ERA login are found
        self.assertEquals(len(result.skipped_era_logins), 1)
        self.assertEquals(len(result.user_auth_dataset_update_result), 0)

        # nih_user_2 and nih_user_3 should have been marked as linked duplicates with same ERA login
        self.assertEquals(len(result.multiple_linked_nih_users), 2)
        self.assertEquals(result.multiple_linked_nih_users[0], ('USERNAME1', self.nih_user_2.pk))
        self.assertEquals(result.multiple_linked_nih_users[1], ('USERNAME1', self.nih_user_3.pk))

        # The service account should not be removed
        self.assertEquals(result.service_account_remove_set, set([]))

