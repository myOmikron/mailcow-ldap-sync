import json
import os
from json.decoder import JSONDecodeError

import requests
from sqlalchemy import Integer, Column, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import ldap


def main(conf, db):
    ldap_conn = ldap.initialize(conf["ldap"]["uri"])
    if conf["ldap"]["allow_self_signed"]:
        ldap_conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    ldap_conn.protocol_version = ldap.VERSION3
    ldap_conn.simple_bind_s(conf["ldap"]["bind_dn"], conf["ldap"]["bind_pw"])
    results = ldap_conn.search_s(conf["ldap"]["user_search_base"], ldap.SCOPE_SUBTREE, conf["ldap"]["user_search_filter"])
    ldap_conn.unbind_s()

    for user in results:
        user_params = user[1]
        uid = user[0]
        first_name = user_params[conf['ldap']['user_mapping']['firstname']][0].decode('utf-8')
        last_name = user_params[conf['ldap']['user_mapping']['lastname']][0].decode('utf-8')
        full_name = f"{first_name} {last_name}"
        mail = user_params[conf['ldap']['user_mapping']['mail']][0].decode('utf-8')
        domain = mail.split('@')[1]
        local_part = mail.split('@')[0]
        password = user_params[conf['ldap']['user_mapping']['password']][0].decode('utf-8')
        if 'quota' in conf['ldap']['user_mapping']:
            quota = user_params[conf['ldap']['user_mapping']['quota']][0].decode('utf-8')
        else:
            quota = "0"
        if not '' == conf['ldap']['user_mapping']['active']:
            active = user_params[conf['ldap']['user_mapping']['active']][0].decode('utf-8')
        else:
            active = "1"
        if not '' == conf['ldap']['user_mapping']['tls_enforce_in']:
            tls_enforce_in = user_params[conf['ldap']['user_mapping']['tls_enforce_in']][0].decode('utf-8')
        else:
            tls_enforce_in = "1"
        if not '' == conf['ldap']['user_mapping']['tls_enforce_out']:
            tls_enforce_out = user_params[conf['ldap']['user_mapping']['tls_enforce_out']][0].decode('utf-8')
        else:
            tls_enforce_out = "1"
        existing = db.query(User).filter_by(
            uid=uid
        ).count()

        if existing == 0:
            existing_mailcow = json.loads(requests.get(
                f"https://{conf['mailcow_host']}/api/v1/get/mailbox/{mail}",
                headers={"X-API-Key": conf['mailcow_api_key']}
            ).text)

            if existing_mailcow:
                data = {
                    "attr": {
                        "active": active,
                        "name": full_name,
                        "password": password,
                        "password2": password,
                        "quota": quota,
                        "tls_enforce_in": tls_enforce_in,
                        "tls_enforce_out": tls_enforce_out
                    },
                    "items": [
                        mail
                    ]
                }
                response = json.loads(requests.post(
                    f"https://{conf['mailcow_host']}/api/v1/edit/mailbox",
                    data=json.dumps(data),
                    headers={
                        "X-API-Key": conf['mailcow_api_key'],
                        "accept": "application/json",
                        "Content-Type": "application/json"
                    }
                ).text)
                if "mailbox_modified" in response[0]["msg"]:
                    pass
            else:
                data = {
                    "active": active,
                    "domain": domain,
                    "local_part": local_part,
                    "name": full_name,
                    "password": password,
                    "password2": password,
                    "quota": quota,
                    "force_pw_update": "0",
                    "tls_enforce_in": tls_enforce_in,
                    "tls_enforce_out": tls_enforce_out
                }
                response = json.loads(requests.post(
                    f"https://{conf['mailcow_host']}/api/v1/add/mailbox",
                    data=json.dumps(data),
                    headers={
                        "accept": "application/json",
                        "Content-Type": "application/json",
                        "X-API-Key": conf['mailcow_api_key']
                    }
                ).text)
                if "mailbox_added" in response[0]["msg"]:
                    pass

            db_user = User(
                uid=uid,
                active=active,
                mail=mail,
                first_name=first_name,
                last_name=last_name,
                password=password,
                quota=quota,
                tls_enforce_in=tls_enforce_in,
                tls_enforce_out=tls_enforce_out
            )
            db.add(db_user)
        else:
            for existing in db.query(User).filter_by(uid=uid):
                existing.active = active
                existing.mail = mail
                existing.first_name = first_name
                existing.last_name = last_name
                existing.password = password
                existing.quota = quota
                existing.tls_enforce_in = tls_enforce_in
                existing.tls_enforce_out = tls_enforce_out
        db.commit()


default_config = {
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


def get_config():
    if os.path.exists("config.json") and os.path.isfile("config.json"):
        with open("config.json") as fh:
            try:
                return json.load(fh)
            except JSONDecodeError:
                print("Malformed config, exiting..")
                exit(1)
    else:
        with open("config.json", "w") as fh:
            json.dump(default_config, fh, indent=2)
            raise Exception("Config was not found, created new one")


if __name__ == '__main__':
    config = get_config()

    Base = declarative_base()

    class User(Base):
        __tablename__ = "user"
        id = Column(Integer, autoincrement=True, unique=True, primary_key=True)
        uid=Column(String)
        active = Column(String)
        mail = Column(String)
        first_name = Column(String)
        last_name = Column(String)
        password = Column(String)
        quota = Column(String)
        tls_enforce_in = Column(String)
        tls_enforce_out = Column(String)


    engine = create_engine(f"sqlite:///mailcow.sqlite3")
    Base.metadata.create_all(engine)
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    main(config, session)
