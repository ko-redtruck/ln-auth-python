# ln-auth-python
From scratch implementation of [LNURL-auth](https://github.com/btcontract/lnurl-rfc/blob/master/lnurl-auth.md)

> [!WARNING]
> This is a (probably) outdated educational project. Do not use in production!
 
- `ecc.py -->` Eclliptic curve and ECDSA
- `der.py -->` Decode DER encoded ECDSA signature
- `bech.py -->` Bech32 encode `lnurl` string
- `app.py -->` Flask server

## How to test it with a real Lightning Network/Bitcoin wallet

1. Install Tor and configure Tor

```
sudo apt install tor
mkdir ~/hidden_service
sudo nano /etc/tor/torrc
```

2. Add two lines to your Tor config

```
HiddenServiceDir /home/your_username/hidden_service/
HiddenServicePort 80 127.0.0.1:5000
```
3. Restart Tor

```
sudo service tor restart
```

4. Clone this repository and install the dependencies

```
git clone https://github.com/ko-redtruck/ln-auth-python.git
cd /ln-auth-python
sudo pip3 install flask pyqrcode
```

5. Run Tor and get your hostname

```
tor
```

Go to your `/hidde_service` dir, open the file `hostname` and copy the onion address and replace the the address in `app.py, line 21` with your own.

6. Run Flask
```
flask run
```

Open `http://127.0.0.1:5000/auth` in your web browser or your `onion_address/auth` in Tor and scan the QR-Code with a wallet that supports `ln-auth`.
