import hvac
import os
import yaml
import json
from cryptography.fernet import Fernet
import base64, hashlib

VAULT_ADDR     = os.environ.get('VAULT_ADDR')
ROLE_ID        = os.environ.get('ROLE_ID')
SECRET_ID      = os.environ.get('SECRET_ID')
VAULT_PREFIX   = os.environ.get('VAULT_PREFIX')
DUMP_ENCRYPTION_PASSWORD = os.environ.get('DUMP_ENCRYPTION_PASSWORD')

class VaultHandler:
    def __init__(self, url, role_id, secret_id, path, enc_password):
        self.url = url
        self.role_id = role_id
        self.secret_id = secret_id
        self.path = path
        self.enc_password = enc_password
        self.client = hvac.Client(url=self.url)
 
        self.client.auth.approle.login(
          role_id = self.role_id,
          secret_id = self.secret_id
        )

        if self.client.is_authenticated():
            pass
        else:
            raise Exception("Vault authentication error!")

    def get_secrets_list(self):
        secrets_list_response = self.client.secrets.kv.v2.list_secrets(
            path = '{0}'.format(self.path)
        )
        return secrets_list_response['data']['keys']

    def print_all_secrets_with_metadata(self):
        for key in self.get_secrets_list():
            print('\nKey is: {0}'.format(key))
            secret_response = self.get_secret(key)
            print(secret_response)

    def _secrets_to_dict(self):
        secrets_dict = {}
        for key in self.get_secrets_list():
            secret_response = self.get_secret(key)
          
            secret_data = {}
            for k in secret_response['data']['data'].keys():
                secret_data[k] = secret_response['data']['data'][k]
          
            secrets_dict[key] = secret_data
        return secrets_dict

    def get_secret(self, key):
        return self.client.secrets.kv.v2.read_secret(
            path='{0}/{1}'.format(self.path, key)
        )

    def print_secrets_from_dict(self):
        secrets_dict = self._secrets_to_dict()
        for x in secrets_dict:
            print ('\n{0}'.format(x))
            for y in secrets_dict[x]:
                print (y,':',secrets_dict[x][y])

    def dump_all_secrets_to_yaml(self, yaml_path='vault_secrets.yml', encrypt_dump=True):
        secrets_dict = self._secrets_to_dict()
        with open(yaml_path, 'w') as outfile:
            yaml.dump(secrets_dict, outfile, default_flow_style=False)
        if encrypt_dump:
          self._encrypt_dump(yaml_path, yaml_path+'.enc')

    def dump_all_secrets_to_json(self, json_path='vault_secrets.json', encrypt_dump=True):
        secrets_dict = self._secrets_to_dict()
        with open(json_path, 'w') as outfile:
            json.dump(secrets_dict, outfile)
        if encrypt_dump:
          self._encrypt_dump(json_path, json_path+'.enc')

    def _password_to_key_64(self):
        encoded_password = self.enc_password.encode()
        key = hashlib.md5(encoded_password).hexdigest()
        return base64.urlsafe_b64encode(key.encode("utf-8"))

    def _encrypt_dump(self, path_to_dump, path_to_encrypted_dump):
        f = Fernet(self._password_to_key_64())
        with open(path_to_dump, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        with open(path_to_encrypted_dump, "wb") as file:
            file.write(encrypted_data)

    def _decrypt_dump(self, path_to_dump, path_to_decrypted_dump):
        f = Fernet(self._password_to_key_64())
        with open(path_to_dump, "rb") as file:
            file_data = file.read()
        decrypted_data = f.decrypt(file_data)
        with open(path_to_decrypted_dump, "wb") as file:
            file.write(decrypted_data)

    def _json_dump_to_dict(self, json_dump_path, encrypted=True):
        new_json_dump_path = json_dump_path
        secrets_dict = {}
        if encrypted:
            self._decrypt_dump(json_dump_path, json_dump_path+'.dec')
            new_json_dump_path = json_dump_path+'.dec'
        with open(new_json_dump_path) as json_file:
            secrets_dict = json.load(json_file)
        return secrets_dict
        

    def _yaml_dump_to_dict(self, yaml_dump_path, encrypted=True):
        new_yaml_dump_path = yaml_dump_path
        secrets_dict = {}
        if encrypted:
            self._decrypt_dump(yaml_dump_path, yaml_dump_path+'.dec')
            new_yaml_dump_path = yaml_dump_path+'.dec'
        with open(new_yaml_dump_path) as yaml_file:
            secrets_dict = json.load(yaml_file)
        return secrets_dict
    
    def _populate_vault_prefix_from_dict(self, secrets_dict, vault_prefix_to_populate):
      for key in secrets_dict:
          self.client.secrets.kv.v2.create_or_update_secret(
              path = '{0}/{1}'.format(vault_prefix_to_populate, key),
              secret = secrets_dict[key],
          )

    def populate_vault_from_dump(self, vault_prefix_to_populate, path_to_dump, dump_format, encoded=True):
        secrets_dict = {}
        if dump_format == 'json':
            secrets_dict = self._json_dump_to_dict(path_to_dump, encoded)
        elif dump_format == 'yaml':
            secrets_dict = self._yaml_dump_to_dict(path_to_dump, encoded)

        self._populate_vault_prefix_from_dict(secrets_dict, vault_prefix_to_populate)

vault = VaultHandler(VAULT_ADDR, ROLE_ID, SECRET_ID, VAULT_PREFIX, DUMP_ENCRYPTION_PASSWORD)
vault.dump_all_secrets_to_json()
# vault.populate_vault_from_dump('testx', 'vault_secrets.json', 'json', False)
