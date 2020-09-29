from flask import Flask
from flask import send_file
from flask import request
from flask import jsonify

import pyqrcode
import secrets

from bech import encode_string
from der import decode_signature

from ecc import elliptic_curve
from ecc import ecdsa
from ecc import point,hex_to_int


"""
REPLACE IT WITH YOUR OWN ADDRESS --> /hidden_severice/hostname
"""

onion_address = "yri5o7gtfa4yabmroogtiyqbulw4g4to3zukuwezpf3er6ifhy5bwcyd.onion"

app = Flask(__name__)
challenges = []


G = point(
    hex_to_int("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798"),
    hex_to_int("483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8")
)

secp256k1 = elliptic_curve(
    0,
    7,
    hex_to_int("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F"),
    hex_to_int("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"),
    G
)


@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route("/auth")
def auth_challenge():
    #32 byte challenge k1
    k1 = secrets.token_hex(32)
    url = "http://"+onion_address+"/signin?tag=login&k1="+k1
    #add k1 to challenges
    challenges.append(k1)

    #bech32 encode string
    bech_32_url = encode_string(url)

    #save as url code and send
    qr = pyqrcode.create(bech_32_url)
    qr.svg("ln-auth-challenge.svg",scale=8)
    return send_file("ln-auth-challenge.svg",mimetype="image/svg+xml")

@app.route("/signin")
def signin():

    error = {
        "status" : False,
        "message" : None
    }

    #long hex string --> r: INT,Base 10: s: INT,Base 10
    der_sig = request.args.get("sig")
    #compressed public key needs to be encodeded
    public_key = ecdsa.compressed_to_point(request.args.get("key"),secp256k1)
    k1 = request.args.get("k1")
    print("sig k1: "+k1)
    if der_sig == None or public_key == None or k1 == None:
        error["status"] = True
        error["message"] = "P_K,Sig or k1 misssing"

    if k1 not in challenges:
        error["status"] = True
        error["message"] = "Invalid challenge"
    else:
        challenge.remove(k1)

    try:
        sig = decode_signature(der_sig)
    except:
        sig = None
        error["status"] = True
        error["message"] = "signature not encoded right"

    try:
        sig_status = ecdsa.raw_verify(public_key,k1,sig,secp256k1)
        if sig_status == False:
            error["status"] = True
            error["message"] = "Signature is invalid"
    except:
        error["status"] = True
        error["message"] = "Signature validation failed"


    if error["status"] == True:
        return jsonify(
            status="ERROR",
            reason=error["message"]
        )
    else:
        return jsonify(
            status = "OK",
            event = "LOGGEDIN"
        )
