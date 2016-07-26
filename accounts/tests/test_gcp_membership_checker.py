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

import logging

from django.test import TestCase

from django.contrib.auth.models import User
from accounts.models import AuthorizedDataset, NIH_User, GoogleProject, ServiceAccount, UserAuthorizedDatasets
from tasks.nih_whitelist_processor.utils import DatasetToACLMapping
from tasks.nih_whitelist_processor.gcp_utils import GoogleProjectMembershipChecker, GoogleProjectRemoveEntry

logging.basicConfig(
    level=logging.INFO
)


DATABASE_ALIAS = 'default'


class TestPublicDatasetServiceAccount(TestCase):
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

        self.nih_user = NIH_User(user=self.auth_user,
                                 NIH_username='USERNAME1',
                                 NIH_assertion='012345689',
                                 dbGaP_authorized=True,
                                 active=True)

        self.nih_user.save()

        self.auth_dataset_123 = AuthorizedDataset(name="dataset1", whitelist_id='phs000123',
                                                  acl_google_group='test_acl', public=True)
        self.auth_dataset_123.save()

        self.project_123 = GoogleProject(project_name="project1",
                                         project_id="123",
                                         big_query_dataset="bq_dataset1")
        self.project_123.save()
        self.project_123.user.add(self.auth_user)

        self.account_123 = ServiceAccount(google_project=self.project_123, service_account="abc_123",
                                          authorized_dataset=self.auth_dataset_123)
        self.account_123.save()

    def test_one_user_auth_dataset(self):
        uad_123 = UserAuthorizedDatasets(nih_user=self.nih_user, authorized_dataset=self.auth_dataset_123)
        uad_123.save()

        gmc = GoogleProjectMembershipChecker(self.dataset_acl_mapping, DATABASE_ALIAS)
        result = gmc.process()

        # The service account should have been skipped, as it is linked to a public dataset
        self.assertEquals(len(result.skipped_service_accounts), 1)

        # No project-specific actions should have been generated
        self.assertEquals(len(result.acl_remove_list), 0)


class TestUnauthorizedUser(TestCase):
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

        self.auth_user_1 = User(first_name='Test', last_name='User', username='test_user', email='test@email.com')
        self.auth_user_1.save()

        self.nih_user = NIH_User(user=self.auth_user_1,
                                 NIH_username='USERNAME1',
                                 NIH_assertion='012345689',
                                 dbGaP_authorized=True,
                                 active=True)

        self.nih_user.save()

        self.auth_user_2 = User(first_name='Test2', last_name='User2', username='test_user_2', email='test2@email.com')
        self.auth_user_2.save()

        self.auth_dataset_123 = AuthorizedDataset(name="dataset1", whitelist_id='phs000123',
                                                  acl_google_group='test_acl', public=False)
        self.auth_dataset_123.save()

        self.project_123 = GoogleProject(project_name="project1",
                                         project_id="123",
                                         big_query_dataset="bq_dataset1")
        self.project_123.save()
        self.project_123.user.add(self.auth_user_1)
        self.project_123.user.add(self.auth_user_2)

        self.account_123 = ServiceAccount(google_project=self.project_123, service_account="abc_123",
                                          authorized_dataset=self.auth_dataset_123)
        self.account_123.save()

    def test_one_user_auth_dataset(self):
        uad_123 = UserAuthorizedDatasets(nih_user=self.nih_user, authorized_dataset=self.auth_dataset_123)
        uad_123.save()

        gmc = GoogleProjectMembershipChecker(self.dataset_acl_mapping, DATABASE_ALIAS)
        result = gmc.process()

        # The service account should not have been skipped, as it is linked to a protected dataset
        self.assertEquals(len(result.skipped_service_accounts), 0)

        self.assertEquals(len(result.acl_remove_list), 1)
        self.assertEquals(result.acl_remove_list[0],
                          GoogleProjectRemoveEntry.from_models(self.project_123, self.account_123, 'acl-phs000123'))


class TestPublicAndProtectedDataset(TestCase):
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

        self.nih_user = NIH_User(user=self.auth_user,
                                 NIH_username='USERNAME1',
                                 NIH_assertion='012345689',
                                 dbGaP_authorized=True,
                                 active=True)

        self.nih_user.save()

        self.auth_dataset_123 = AuthorizedDataset(name="dataset1", whitelist_id='phs000123',
                                                  acl_google_group='acl-phs000123', public=True)
        self.auth_dataset_123.save()

        self.project_123 = GoogleProject(project_name="project1",
                                         project_id="123",
                                         big_query_dataset="bq_dataset1")
        self.project_123.save()
        self.project_123.user.add(self.auth_user)

        self.account_123 = ServiceAccount(google_project=self.project_123, service_account="abc_123",
                                          authorized_dataset=self.auth_dataset_123)
        self.account_123.save()

        self.auth_dataset_456 = AuthorizedDataset(name="dataset1", whitelist_id='phs000456',
                                                  acl_google_group='acl-phs000456', public=False)
        self.auth_dataset_456.save()

        self.account_456 = ServiceAccount(google_project=self.project_123, service_account="456@institution.org",
                                          authorized_dataset=self.auth_dataset_456)
        self.account_456.save()

    def test_both_accounts_authorized(self):
        uad_123 = UserAuthorizedDatasets(nih_user=self.nih_user, authorized_dataset=self.auth_dataset_123)
        uad_123.save()

        uad_456 = UserAuthorizedDatasets(nih_user=self.nih_user, authorized_dataset=self.auth_dataset_456)
        uad_456.save()

        gmc = GoogleProjectMembershipChecker(self.dataset_acl_mapping, DATABASE_ALIAS)
        result = gmc.process()

        # Account 'abc_123' should have been skipped, as it is associated to a public dataset
        self.assertEquals(len(result.skipped_service_accounts), 1)
        self.assertEquals(result.skipped_service_accounts[0], "abc_123")

        self.assertEquals(len(result.acl_remove_list), 0)

    def test_protected_account_not_authorized(self):
        uad_123 = UserAuthorizedDatasets(nih_user=self.nih_user, authorized_dataset=self.auth_dataset_123)
        uad_123.save()

        gmc = GoogleProjectMembershipChecker(self.dataset_acl_mapping, DATABASE_ALIAS)
        result = gmc.process()

        self.assertEquals(len(result.skipped_service_accounts), 1)
        self.assertEquals(result.skipped_service_accounts[0], "abc_123")

        # Only 'abc_456' should have been marked for removal
        self.assertEquals(len(result.acl_remove_list), 1)
        self.assertEquals(result.acl_remove_list[0],
                          GoogleProjectRemoveEntry.from_models(self.project_123, self.account_456, 'acl-phs000456'))

