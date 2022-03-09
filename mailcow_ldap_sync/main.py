import argparse
import json
import os
import logging

import requests
from sqlalchemy import Integer, Column, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import ldap

logger = logging.getLogger("mailcow_ldap_sync")


def is_diff(mailcow_response, active, full_name, quota, tls_enforce_in, tls_enforce_out):
    return mailcow_response["active"] != active or \
           mailcow_response["name"] != full_name or \
           mailcow_response["quota"] != quota or \
           mailcow_response["attributes"]["tls_enforce_in"] != str(tls_enforce_in) or \
           mailcow_response["attributes"]["tls_enforce_out"] != str(tls_enforce_out)


def main(conf, db, change_only_by_ldap=False):
    if conf["ldap"]["allow_self_signed"]:
        logger.info("Allowing selfsigned certs")
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    logger.info(f"Connecting to {conf['ldap']['uri']}")
    ldap_conn = ldap.initialize(conf["ldap"]["uri"])
    logger.info(f"Connected to {conf['ldap']['uri']}")
    ldap_conn.protocol_version = ldap.VERSION3
    logger.info(f"Trying to bind as {conf['ldap']['bind_dn']}")
    ldap_conn.simple_bind_s(conf["ldap"]["bind_dn"], conf["ldap"]["bind_pw"])
    logger.info(f"Successfully bind as {conf['ldap']['bind_dn']}")
    results = ldap_conn.search_s(conf["ldap"]["user_search_base"], ldap.SCOPE_SUBTREE,
                                 conf["ldap"]["user_search_filter"])
    logger.debug(f"Search results: {results}")
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
            logger.debug(f"LDAP user {uid} does not exist in local db")
            existing_mailcow = requests.get(
                f"https://{conf['mailcow_host']}/api/v1/get/mailbox/{mail}",
                headers={"X-API-Key": conf['mailcow_api_key']}
            ).json()

            if existing_mailcow:
                logger.debug(f"LDAP user {uid} does exist in mailcow")
                if not change_only_by_ldap or is_diff(
                        existing_mailcow, active, full_name, quota, tls_enforce_in, tls_enforce_out
                ):
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
                    response = requests.post(
                        f"https://{conf['mailcow_host']}/api/v1/edit/mailbox",
                        json=data,
                        headers={
                            "X-API-Key": conf['mailcow_api_key'],
                            "accept": "application/json",
                            "Content-Type": "application/json"
                        }
                    ).json()
                    if "mailbox_modified" in response[0]["msg"]:
                        logger.info(f"LDAP user {uid} was modified in mailcow")
            else:
                logger.debug(f"LDAP user {uid} does not exist in mailcow")
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
                response = requests.post(
                    f"https://{conf['mailcow_host']}/api/v1/add/mailbox",
                    json=data,
                    headers={
                        "accept": "application/json",
                        "Content-Type": "application/json",
                        "X-API-Key": conf['mailcow_api_key']
                    }
                ).json()
                if "mailbox_added" in response[0]["msg"]:
                    logger.info(f"LDAP user {uid} was added in mailcow")

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
            logger.debug(f"LDAP user {uid} was added to local db")
        else:
            logger.debug(f"LDAP user {uid} was found in local db")
            for existing in db.query(User).filter_by(uid=uid):
                existing_mailcow = requests.get(
                    f"https://{conf['mailcow_host']}/api/v1/get/mailbox/{mail}",
                    headers={"X-API-Key": conf['mailcow_api_key']}
                ).json()

                if existing_mailcow:
                    if not change_only_by_ldap or is_diff(
                            existing_mailcow, active, full_name, quota, tls_enforce_in, tls_enforce_out
                    ):
                        logger.debug(f"LDAP user {uid} does exist in mailcow")
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
                        logger.info(requests.get(
                            f"https://{conf['mailcow_host']}/api/v1/get/mailbox/{mail}",
                            headers={"X-API-Key": conf['mailcow_api_key']}
                        ).json())
                        response = requests.post(
                            f"https://{conf['mailcow_host']}/api/v1/edit/mailbox",
                            json=data,
                            headers={
                                "X-API-Key": conf['mailcow_api_key'],
                                "accept": "application/json",
                                "Content-Type": "application/json"
                            }
                        ).json()
                        logger.info(requests.get(
                            f"https://{conf['mailcow_host']}/api/v1/get/mailbox/{mail}",
                            headers={"X-API-Key": conf['mailcow_api_key']}
                        ).json())
                        if "mailbox_modified" in response[0]["msg"]:
                            logger.info(f"LDAP user {uid} was modified in mailcow")
                else:
                    logger.debug(f"LDAP user {uid} does not exist in mailcow")
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
                    response = requests.post(
                        f"https://{conf['mailcow_host']}/api/v1/add/mailbox",
                        json=data,
                        headers={
                            "accept": "application/json",
                            "Content-Type": "application/json",
                            "X-API-Key": conf['mailcow_api_key']
                        }
                    ).json()
                    if "mailbox_added" in response[0]["msg"]:
                        logger.info(f"LDAP user {uid} was added in mailcow")
                existing.active = active
                existing.mail = mail
                existing.first_name = first_name
                existing.last_name = last_name
                existing.password = password
                existing.quota = quota
                existing.tls_enforce_in = tls_enforce_in
                existing.tls_enforce_out = tls_enforce_out
                logger.debug(f"LDAP user {uid} was updated in local db")

        db.commit()
    db_user = [user.uid for user in db.query(User).all()]
    ldap_user = [user[0] for user in results]
    for user in db_user:
        if user not in ldap_user:
            for x in db.query(User).filter_by(uid=user):
                logger.debug(f"Local user {x.uid} was not found in LDAP")
                data = [
                    x.mail
                ]
                response = requests.post(
                    f"https://{conf['mailcow_host']}/api/v1/delete/mailbox",
                    json=data,
                    headers={
                        "accept": "application/json",
                        "Content-Type": "application/json",
                        "X-API-Key": conf['mailcow_api_key']
                    }
                ).json()
                if "mailbox_removed" in response[0]["msg"]:
                    logger.info(f"Local user {x.uid} was deleted in mailcow")
                    db.delete(x)
                    logger.debug(f"Local user {x.uid} was deleted in local db")
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
            except json.JSONDecodeError:
                print("Malformed config, exiting..")
                exit(1)
    else:
        with open("config.json", "w") as fh:
            json.dump(default_config, fh, indent=2)
            raise Exception("Config was not found, created new one")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--update-only-on-change-by-ldap",
        action="store_true",
        dest="change",
        help="Specify, if an updated should only be invoked, if any diff between LDAP, DB or mailcow is recognized."
             "Caution: As passwords can only be retrieved by LDAP, there's no way to check, if the password was changed"
             "in mailcow."
    )
    args = parser.parse_args()

    config = get_config()
    logging.basicConfig(filename='mailcow_ldap_sync.log', level=logging.INFO)

    Base = declarative_base()


    class User(Base):
        __tablename__ = "user"
        id = Column(Integer, autoincrement=True, unique=True, primary_key=True)
        uid = Column(String)
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

    main(config, session, change_only_by_ldap=args.change)
