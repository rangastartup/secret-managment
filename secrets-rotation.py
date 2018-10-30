#!/usr/bin/env python

# Copyright 2018 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Demonstrates how to perform basic operations with Google Cloud IAM
service account keys.

For more information, see the documentation at
https://cloud.google.com/iam/docs/creating-managing-service-account-keys.
"""
import argparse
import os
import base64
import datetime
import pprint
import googleapiclient.discovery
#import cloudstorage as gcs
import io
import json
#import secretconfig



from google.oauth2 import service_account
import googleapiclient.discovery

# Imports the Google Cloud client library
from google.cloud import storage

credentials = service_account.Credentials.from_service_account_file(
    filename=os.environ['GOOGLE_APPLICATION_CREDENTIALS'],
    scopes=['https://www.googleapis.com/auth/cloud-platform'])
service = googleapiclient.discovery.build(
    'iam', 'v1', credentials=credentials)


# [START iam_create_key]
def create_key(service_account_email):
    """Creates a key for a service account."""
    # pylint: disable=no-member
    key = service.projects().serviceAccounts().keys().create(
        name='projects/-/serviceAccounts/' + service_account_email, body={}
        ).execute()
    plaintext = json.dumps(key)
    print "going to encrypt"
    encrypt(project_id, location_id, key_ring_id, crypto_key_id,
    plaintext, ciphertext_file_name)
    print "encryption complete"
    upload_blob('secrets-jenkins',ciphertext_file_name,'jenkins')
    print('upload completed ')
# [END iam_create_key]


# [START iam_list_keys]
def list_keys(service_account_email):
    """Lists all keys for a service account."""

    # pylint: disable=no-member
    keys = service.projects().serviceAccounts().keys().list(
        name='projects/-/serviceAccounts/' + service_account_email).execute()

    for key in keys['keys']:
        print('Key: ' + key['name'])

# [END iam_list_keys]


# [START iam_delete_key]
def delete_key(full_key_name):
    """Deletes a service account key."""

    # pylint: disable=no-member
    service.projects().serviceAccounts().keys().delete(
        name=full_key_name).execute()

    print('Deleted key: ' + full_key_name)
# [END iam_delete_key]

# [START iam_list_keys]
def clean_keys(service_account_email):
    """Lists all keys for a service account."""

    # pylint: disable=no-member
    keys = service.projects().serviceAccounts().keys().list(
        name='projects/-/serviceAccounts/' + service_account_email).execute()
    print "before delete"
    for key in keys['keys']:
        print('Key: ' + key['name'] + key['validAfterTime'])
        if key['validAfterTime'] > '2018-10-26':
           delete_key(key['name'])
# [END iam_list_keys]

# [START storage_upload_file]
def upload_blob(bucket_name, source_file_name, destination_blob_name):
    """Uploads a file to the bucket.
    :rtype: object
    """
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

    # print('File {} uploaded to {}.'.format(
    #     source_file_name,
    #     destination_blob_name))


# [END storage_upload_file]

# [START kms_encrypt]
def encrypt(project_id, location_id, key_ring_id, crypto_key_id,
            plaintext, ciphertext_file_name):
    """Encrypts data from plaintext_file_name using the provided CryptoKey and
    saves it to ciphertext_file_name so it can only be recovered with a call to
    decrypt.
    """

    # Creates an API client for the KMS API.
    kms_client = googleapiclient.discovery.build('cloudkms', 'v1')

    # The resource name of the CryptoKey.
    name = 'projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(
        project_id, location_id, key_ring_id, crypto_key_id)

    # Read data from the input file.
    #with io.open(plaintext_file_name, 'rb') as plaintext_file:
    #    plaintext = plaintext_file.read()

    # Use the KMS API to encrypt the data.
    crypto_keys = kms_client.projects().locations().keyRings().cryptoKeys()
    request = crypto_keys.encrypt(
        name=name,
        body={'plaintext': base64.b64encode(plaintext).decode('ascii')})
    response = request.execute()
    ciphertext = base64.b64decode(response['ciphertext'].encode('ascii'))

    # Write the encrypted data to a file.
    with io.open(ciphertext_file_name, 'wb') as ciphertext_file:
        ciphertext_file.write(ciphertext)

    #print('Saved ciphertext to {}.'.format(ciphertext))
    print('Saved ciphertext to {}.'.format(ciphertext_file_name))
# [END kms_encrypt]

# [START iam_create_key]
def reterive_key(ciphertext):
    """Creates a key for a service account."""
    # bucket_name = 'secrets-jenkins'
    # source_blob_name = 'jenkins'
    # bucket_file_name = 'downloaded_blob'

    download_blob(bucket_name,source_blob_name, bucket_file_name )

    print "Encrypted key: " + ciphertext
    # project_id = 'secrets-managment'
    # location_id = 'global'
    # key_ring_id ='terraform-jenkins-secret'
    # crypto_key_id = 'terraform-jenkins-secret-key'
    # decrypted_file_name = 'decrypted.json'

    decrypt(project_id, location_id, key_ring_id, crypto_key_id,
            bucket_file_name, decrypted_file_name)

    print('decryption complete : ')
# [END iam_create_key]

# [START kms_decrypt]
def decrypt(project_id, location_id, key_ring_id, crypto_key_id,
            ciphertext_file_name, plaintext_file_name):
    """Decrypts data from ciphertext_file_name that was previously encrypted
    using the provided CryptoKey and saves it to plaintext_file_name."""

    # Creates an API client for the KMS API.
    kms_client = googleapiclient.discovery.build('cloudkms', 'v1')

    # The resource name of the CryptoKey.
    name = 'projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(
        project_id, location_id, key_ring_id, crypto_key_id)

    # Read encrypted data from the input file.
    with io.open(ciphertext_file_name, 'rb') as ciphertext_file:
        ciphertext = ciphertext_file.read()

    # Use the KMS API to decrypt the data.
    crypto_keys = kms_client.projects().locations().keyRings().cryptoKeys()
    request = crypto_keys.decrypt(
        name=name,
        body={'ciphertext': base64.b64encode(ciphertext).decode('ascii')})
    response = request.execute()
    plaintext = base64.b64decode(response['plaintext'].encode('ascii'))

    # Write the decrypted data to a file.
    with io.open(plaintext_file_name, 'wb') as plaintext_file:
        plaintext_file.write(plaintext)

    print('Saved plaintext to {}.'.format(plaintext_file_name))
# [END kms_decrypt]

def download_blob(bucket_name, source_blob_name, destination_file_name):
    """Downloads a blob from the bucket."""
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(source_blob_name)
    blob = blob.download_to_filename(destination_file_name)
    print "downloaded_blob"
    print('Blob {} downloaded to {}.'.format(
        source_blob_name,
        destination_file_name))

# [START read]

def read_file(self, filename):
    self.response.write('Reading the full file contents:\n')

    gcs_file = gcs.open(filename)
    contents = gcs_file.read()
    gcs_file.close()
    self.response.write(contents)
# [END read]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(dest='command')

    create_key_parser = subparsers.add_parser(
        'create', help=create_key.__doc__)
    create_key_parser.add_argument('service_account_email')

    list_keys_parser = subparsers.add_parser(
        'list', help=list_keys.__doc__)
    list_keys_parser.add_argument('service_account_email')

    delete_key_parser = subparsers.add_parser(
        'delete', help=delete_key.__doc__)
    delete_key_parser.add_argument('full_key_name')

    clean_keys_parser = subparsers.add_parser(
        'clean', help=clean_keys.__doc__)
    clean_keys_parser.add_argument('service_account_email')

    reterive_key_parser = subparsers.add_parser(
        'reterive', help=reterive_key.__doc__)
    reterive_key_parser.add_argument('service_account_email')

    service_account_email = 'secrects-terrraform-admin@secrets-managment.iam.gserviceaccount.com'

    project_id = 'secrets-managment'
    location_id = 'global'
    key_ring_id ='terraform-jenkins-secret'
    crypto_key_id = 'terraform-jenkins-secret-key'
    ciphertext_file_name = 'secrets.json.encrypted'
    decrypted_file_name = 'secrets.json.decrypted'

    # GCP bucket details to store the encrypted secret
    bucket_name = 'secrets-jenkins'
    source_blob_name = 'jenkins'

    # File name to downlaod the encrypted secret file
    bucket_file_name = 'secrets.json.downloaded'

    args = parser.parse_args()

    if args.command == 'list':
        list_keys(args.service_account_email)
    elif args.command == 'create':
        create_key(args.service_account_email)
    elif args.command == 'delete':
        delete_key(args.full_key_name)
    elif args.command == 'clean':
        clean_keys(args.service_account_email)
    elif args.command == 'reterive':
        reterive_key(args.service_account_email)