import os
import uuid
import json
import base64
import random
import sqlite3
from typing import Dict
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, Response
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from models import Credential, UserAccount

app = Flask(__name__)

# rp_id = "free5gmano.nutc-imac.com"
# origin = "https://free5gmano.nutc-imac.com"

rp_id = "zero-trust-test.nutc-imac.com"
origin = "https://zero-trust-test.nutc-imac.com"

# rp_id = "10.20.1.63"
# origin = "http://10.20.1.63"

# rp_id = "free5gmanowebui.nutc-imac.com"
# origin = "https://free5gmanowebui.nutc-imac.com"


rp_name = "ubuntu"


in_memory_db: Dict[str, UserAccount] = {}


current_registration_challenge = None
current_authentication_challenge = None


@app.route("/")
def index():
    context = {
        "username": username,
    }
    return render_template("index.html", **context)

@app.route("/generate-registration-options", methods=["POST"])
def registerFidoOptions():
    print("generate-registration-options")
    user_data = request.get_json()
    bundle_id = user_data.get("username")
    registration_options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=bundle_id,
        user_name=bundle_id,
        exclude_credentials=[
            {"id": "", "transports": [], "type": "public-key"}
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
        challenge=str(random.randint(1000000, 9999999)).encode('utf-8')
    )
    in_memory_db[bundle_id] = UserAccount(
        id=bundle_id,
        challenge=registration_options.challenge,
        credentials=[]
    )
    return options_to_json(registration_options)

@app.route("/verify-registration-response", methods=["POST"])
def registerOptionResponse():
    user_data = request.get_json()
    raw_id = user_data.get("rawId").split("=")[0]
    user_data["id"] = raw_id
    user_data["raw_id"] = raw_id
    bundle_id = user_data.get("username")
    user = in_memory_db[bundle_id]
    print("================in_memory_db===================")
    print(in_memory_db)
    print("================in_memory_db===================")
    try:
        # pendingverification_data = request.get_data()
        pendingverification_data = json.dumps(user_data, indent=2).encode('utf-8')
        credential_data = RegistrationCredential.parse_raw(
            pendingverification_data)
        verification_fun = verify_registration_response(
            credential=credential_data,
            expected_rp_id=rp_id,
            expected_origin=origin,
            expected_challenge=str(base64.b64encode(user.challenge), encoding='utf-8').split("==")[0].encode('utf-8')
        )
        new_credential = Credential(
            id=verification_fun.credential_id,
            public_key=verification_fun.credential_public_key,
            sign_count=verification_fun.sign_count,
            transports=json.loads(pendingverification_data).get("transports", []),
        )
        user.credentials.append(new_credential)
    except Exception as e:
        print(e)
        return {
            "verified": False,
            "msg": str(e)
            }

    return {"verified": True, "username": bundle_id}

@app.route("/generate-authentication-options", methods=["POST"])
def sigInOptionRequest():
    print("generate-authentication-options")
    user_data = request.get_json()
    bundle_id = user_data.get("username")
    user = in_memory_db[bundle_id]
    login_options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            {"type": "public-key", "id": cred.id, "transports": cred.transports}
            for cred in user.credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
        challenge=str(random.randint(1000000, 9999999)).encode('utf-8')
    )
    in_memory_db[bundle_id].challenge = login_options.challenge
    return options_to_json(login_options)


@app.route("/verify-authentication-response", methods=["POST"])
def hander_verify_authentication_response():
    print("verify-authentication-response")
    user_data = request.get_json()
    raw_id = user_data.get("rawId").split("=")[0]
    user_data["id"] = raw_id
    user_data["raw_id"] = raw_id
    bundle_id = user_data.get("username")
    user = in_memory_db[bundle_id]
    print("================in_memory_db===================")
    print(in_memory_db)
    print("================in_memory_db===================")
    pendingverification_data = json.dumps(user_data, indent=2).encode('utf-8')

    pendingverification_credential = AuthenticationCredential.parse_raw(
        pendingverification_data)
    try:
        user_credential = None
        for _cred in user.credentials:
            if _cred.id == pendingverification_credential.raw_id:
                user_credential = _cred
        if user_credential is None:
            raise Exception("Could not find corresponding public key in DB")

        verification_fun = verify_authentication_response(
            credential=pendingverification_credential,
            expected_challenge=str(base64.b64encode(user.challenge), encoding='utf-8').split("==")[0].encode('utf-8'),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=user_credential.public_key,
            credential_current_sign_count=user_credential.sign_count,
            require_user_verification=True,
        )    
        user_credential.sign_count = verification_fun.new_sign_count
        default = {
            "status": "login",
            "verified": True,
            "user_credential.sign_count": user_credential.sign_count,
        }
    except Exception as e:
        print(e)
        return {
            "verified": False,
            "msg": str(e)
            }
    return default

@app.route("/.well-known/apple-app-site-association", methods=["GET"])
def apple_app_site_association():
    return {
    "webcredentials": {
        "apps": ["NHPJ3CC74D.com.leoho.passkeysexample", "S8FBP4YLUA.com.leoho.passkeysexample", "352B3NNBK2.com.tekpass.keep"],
    }
}

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0', port=8080)