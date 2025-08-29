Postman walkthrough (clicks + small scripts)
Environment vars

Create these in Postman:
host_app   = https://api.streamdeploy.com
host_device= https://device.streamdeploy.com
orgid      = <org id>
group      = <group id>          // <- this is an ID
user_jwt   = <user bearer token>

# paste later:
csr_pem    = <full CSR PEM including BEGIN/END>

# will be set by scripts:
bootstrap_token =
nonce =
ca_bundle =
csr_base64 =

1) Enroll start → nonce (+ CA bundle)

POST {{host_app}}/v1-app/enroll/start

Headers: Content-Type: application/json

Body (raw):
{ "enrollment_token": "{{bootstrap_token}}" }

Tests:
const j = pm.response.json();
pm.environment.set('nonce', j.nonce);
pm.environment.set('ca_bundle', j.ca_bundle);

Here, all you need to do is let device, with the token from frontend, contact backend.
You will get nonce and ca_bundle

2) Generate key + CSR (EC P-256, SPIFFE SAN)
export KEY=device.key
export CSR=device.csr

openssl ecparam -name prime256v1 -genkey -noout -out "$KEY"

cat > san.cnf <<EOF
[ req ]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[ dn ]
CN = $DEVICE_ID
[ v3_req ]
subjectAltName = URI:spiffe://streamdeploy/device/$DEVICE_ID
EOF

openssl req -new -key "$KEY" -out "$CSR" -config san.cnf

openssl req -in "$CSR" -noout -text -verify | sed -n '1,80p'   # sanity check

Here, you should have a .csr file (device.csr)

3) Enroll CSR via csr_base64

YOU NEED TO CONVERT .csr FILE TO BASE64 STRING.

Here, postman does it automatically via pre-request Script:

let csr = pm.environment.get('csr_pem') || '';
csr = csr.replace(/\uFEFF/g,'')
         .replace(/```(?:pem|csr)?/gi,'').replace(/```/g,'')
         .replace(/\r\n/g,'\n').replace(/\r/g,'\n');
const m = csr.match(/-+BEGIN (NEW )?CERTIFICATE REQUEST-+[\s\S]*?-+END (NEW )?CERTIFICATE REQUEST-+/);
if (!m) throw new Error('CSR PEM block not found. Paste full BEGIN/END CERTIFICATE REQUEST.');
csr = m[0].replace('BEGIN NEW CERTIFICATE REQUEST','BEGIN CERTIFICATE REQUEST')
          .replace('END NEW CERTIFICATE REQUEST','END CERTIFICATE REQUEST');
pm.environment.set('csr_base64', Buffer.from(csr, 'utf8').toString('base64'));


POST {{host_app}}/v1-app/enroll/csr

Headers: Content-Type: application/json

Body (raw):
{
  "token": "{{bootstrap_token}}",
  "nonce": "{{nonce}}",
  "csr_base64": "{{csr_base64}}"
}

Response 200: cert_pem, chain[], not_after.


4. Healthcheck
Put the cert_pem in the same file with all the certs of chain[], seperated by \n in order.

You can verify any certificate file's formatting by using the following command:
openssl x509 -in your-crt -noout -text | sed -n '1,40p'

In postman: Configure Postman client cert
Settings → Certificates → Add:
Host: device.streamdeploy.com
CRT file: device.fullchain.crt
KEY file: device.key (the private key you used for the CSR)

Test:

POST {{host_device}}/v1-device/heartbeat
body: {
  "status": "normal",
  "agent_setting": {
    "heartbeat_frequency": "5m",
    "update_frequency": "30s"
  },
  "metrics": {
    "cpu_pct": 12.3,
    "mem_pct": 41.7,
    "temp_c": 53.2
  }
}

Expect 202 {"ok":true}.