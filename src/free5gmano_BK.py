import os
import uuid
import json
import base64
from typing import Dict
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

rp_id = "zero-trust-test.nutc-imac.com""
origin = "https://zero-trust-test.nutc-imac.com"

# rp_id = "10.20.1.63"
# origin = "http://10.20.1.63"

# rp_id = "free5gmanowebui.nutc-imac.com"
# origin = "https://free5gmanowebui.nutc-imac.com"


rp_name = "ubuntu"

user = "012345"

user_id = user
username = f"{user}@{rp_id}"

in_memory_db: Dict[str, UserAccount] = {}
logged_in_user_id = user_id
in_memory_db[user_id] = UserAccount(
    id=user_id,
    username=username,
    credentials=[],
)

current_registration_challenge = None
current_authentication_challenge = None


@app.route("/")
def index():
    context = {
        "username": username,
    }
    return render_template("index.html", **context)


# generate-registration-options
# @app.route("/registerFidoOptions", methods=["GET"])
@app.route("/generate-registration-options", methods=["GET"])
def registerFidoOptions():
    print("generate-registration-options")
    global current_registration_challenge
    global logged_in_user_id
    user = in_memory_db[logged_in_user_id]
    # print(user)
    # print(dir(user))
    registration_options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user.id,
        user_name=user.username,
        exclude_credentials=[
            {"id": cred.id, "transports": cred.transports, "type": "public-key"}
            for cred in user.credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
        challenge=b"1234567890",
    )

    # current_registration_challenge = registration_options.challenge
    # print("current_registration_challenge = %s" % current_registration_challenge)
    return options_to_json(registration_options)


# verify-registration-response
# @app.route("/registerOptionResponse", methods=["POST"])
@app.route("/verify-registration-response", methods=["POST"])
def registerOptionResponse():
    print("verify-registration-response")
    global current_registration_challenge
    global logged_in_user_id
    pendingverification_data = request.get_data()


    credential_data = RegistrationCredential.parse_raw(
        pendingverification_data)
    print(base64url_to_bytes(
        "CeTWogmg0cchuiYuFrv8DXXdMZSIQRVZJOga_xayVVEcBj0Cw3y73yhD4FkGSe-RrP6hPJJAIm3LVien4hXELg"
        ))
    verification_fun = verify_registration_response(
        credential=credential_data,
        # expected_challenge=current_registration_challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        expected_challenge=str(base64.b64encode(b"1234567890"), encoding='utf-8').split("==")[0].encode('utf-8')
        # expected_challenge=base64.b64encode("1234567890".encode('UTF-8')),
        # expected_challenge=base64url_to_bytes(
        # b"1234567890"
        # ),
    )
    
    # try:
    #     credential_data = RegistrationCredential.parse_raw(
    #         pendingverification_data)
    #     verification_fun = verify_registration_response(
    #         credential=credential_data,
    #         # expected_challenge=current_registration_challenge,
    #         expected_rp_id=rp_id,
    #         expected_origin=origin,
    #         expected_challenge=base64url_to_bytes(
    #         "CeTWogmg0cchuiYuFrv8DXXdMZSIQRVZJOga_xayVVEcBj0Cw3y73yhD4FkGSe-RrP6hPJJAIm3LVien4hXELg"
    #         ),
    #     )
    # except Exception as e:
    #     print(e)
    #     return {"msg": str(e)}

    user = in_memory_db[logged_in_user_id]

    new_credential = Credential(
        id=verification_fun.credential_id,
        public_key=verification_fun.credential_public_key,
        sign_count=verification_fun.sign_count,
        transports=json.loads(pendingverification_data).get("transports", []),
    )

    user.credentials.append(new_credential)
    print("==ver_user==")
    print(user)

    return {"verified": True, "username": username}


user = in_memory_db[logged_in_user_id]
# @app.route("/sigInOptionRequest", methods=["GET"])


@app.route("/generate-authentication-options", methods=["GET"])
def sigInOptionRequest():
    print("generate-authentication-options")
    global current_authentication_challenge
    global logged_in_user_id

    login_options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            {"type": "public-key", "id": cred.id, "transports": cred.transports}
            for cred in user.credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
        challenge=b"1234567890",
    )
    # current_authentication_challenge = login_options.challenge
    # print("current_authentication_challenge = %s" % current_authentication_challenge)
    # print("decode_a_c = %s" % base64url_to_bytes(current_authentication_challenge))
    return options_to_json(login_options)


@app.route("/verify-authentication-response", methods=["POST"])
def hander_verify_authentication_response():
    print("verify-authentication-response")
    global current_authentication_challenge
    global logged_in_user_id
    pendingverification_data = request.get_data()
    print("pendingverification_data = %s" % pendingverification_data)

    pendingverification_credential = AuthenticationCredential.parse_raw(
        pendingverification_data)
    print("pendingverification_credential = %s" % pendingverification_credential)
    user = in_memory_db[logged_in_user_id]
    user_credential = None
    print("==au_user==")
    print(user)
    for _cred in user.credentials:
        if _cred.id == pendingverification_credential.raw_id:
            user_credential = _cred
    if user_credential is None:
        raise Exception("Could not find corresponding public key in DB")

    verification_fun = verify_authentication_response(
        credential=pendingverification_credential,
        # expected_challenge=current_authentication_challenge,
        expected_challenge=str(base64.b64encode(b"1234567890"), encoding='utf-8').split("==")[0].encode('utf-8'),
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=user_credential.public_key,
        credential_current_sign_count=user_credential.sign_count,
        require_user_verification=True,
    )    
    # try:
    #     pendingverification_credential = AuthenticationCredential.parse_raw(
    #         pendingverification_data)
    #     user = in_memory_db[logged_in_user_id]
    #     user_credential = None
    #     print("==au_user==")
    #     print(user)
    #     for _cred in user.credentials:
    #         if _cred.id == pendingverification_credential.raw_id:
    #             user_credential = _cred

    #     if user_credential is None:
    #         raise Exception("Could not find corresponding public key in DB")

    #     verification_fun = verify_authentication_response(
    #         credential=pendingverification_credential,
    #         expected_challenge=current_authentication_challenge,
    #         expected_rp_id=rp_id,
    #         expected_origin=origin,
    #         credential_public_key=user_credential.public_key,
    #         credential_current_sign_count=user_credential.sign_count,
    #         require_user_verification=True,
    #     )
    # except Exception as e:
    #     print(e)
    #     return {"msg": str(e)}
    print("ver_ok")
    user_credential.sign_count = verification_fun.new_sign_count

    default = {
        "status": "login",
        "verified": True,
        "user_credential.sign_count": user_credential.sign_count,
    }

    return default

@app.route("/.well-known/apple-app-site-association", methods=["GET"])
def apple_app_site_association():
    return {
    "webcredentials": {
        "apps": ["NHPJ3CC74D.com.leoho.passkeysexample", "S8FBP4YLUA.com.leoho.passkeysexample"],
    }
}

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0', port=8080)