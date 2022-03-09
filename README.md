# mailcow-ldap-sync

This script provides a way to synchronize your LDAP users into mailcow. It is based on an intermediate database (sqlite3 by default) to compare the values retrieved by LDAP with the current ones.
It also compares the values in mailcow with its intermediate database and correct the values if needed.

## Installation

There are following prerequisites:
- `python3`
- `python3-pip`
- `python-dev`
- `libldap2-dev`
- `libsasl2-dev`
- `libssl-dev`
- `python3-venv`

```
python3 -m venv venv
venv/bin/python3 -m pip install -r requirements.txt
```
## Setup

First, a config has to be generated. This can be done by executing the script once. 
In your current working directory appear a `config.json`:

Enter your credentials for the LDAP server (The user has to be able to fetch the password hashes) and set the `user_mapping` attributes to its corresponding field names. As stated in the comment, leave those empty you don't plan to use. 

```
{
    "ldap": {
        "uri": "ldap://ldap.example.com",
        "allow_self_signed": False,
        "bind_dn": "",
        "bind_pw": "",
        "user_search_base": "",
        "user_search_filter": "",
        "user_mapping": {
            "mail": "mail",
            "firstname": "givenName",
            "lastname": "sn",
            "password": "userPassword",
            "quota": "MailQuota",
            # Leave empty to not use
            "active": "",
            "tls_enforce_in": "",
            "tls_enforce_out": "",
        }
    },
    "mailcow_host": "mail.example.com",
    "mailcow_api_key": ""
}
```

## Usage

As this script only syncs users once, it has be executed repeatedly.
The easiest way to archive this is to execute the script with a cron job in the interval the users should be synced.

**Note**:
You have to `cd` first in the directory as the script generates a few files relative to the current working directory.

### Arguments:

As all users are overwritten constantly, I added the option `--update-only-on-change-by-ldap` to allow
updates only on a diff between data retrieved by LDAP and mailcow.

**Caution**:

As mailcow does not respond with password hashes, there's no way to detect a changed password in mailcow. 
Only attributes like `active`, `quota` and so on are checked. 