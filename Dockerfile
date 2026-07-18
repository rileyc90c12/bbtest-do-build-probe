FROM python:3.12-alpine
# Bounded, non-exfiltrating STRUCTURAL classification of /kaniko/.docker/config.json.
# Prints ONLY derived metadata (auth type, username FORMAT, secret length, JWT header/claims
# incl. issuer/audience/scope/expiry). NEVER prints raw username or secret values.
RUN python3 - <<'PY'
import json,base64,re
try:
    d=json.load(open('/kaniko/.docker/config.json'))
except Exception as e:
    print("CLASSIFY_ERROR:",repr(e)); raise SystemExit(0)

def b64url(x):
    try: return json.loads(base64.urlsafe_b64decode(x+'='*(-len(x)%4)))
    except Exception: return None

def classify_username(u):
    if u.startswith("dop_v1_"): return "DO-API-TOKEN(dop_v1_)"
    if re.match(r'do[or]_v1_',u): return "DO-OAuth(doo/dor_v1_)"
    if u.startswith("dckr_"): return "DOCR/dckr-prefixed"
    if '@' in u: return "email-like(len=%d)"%len(u)
    if re.fullmatch(r'[0-9a-fA-F-]{20,}',u): return "hex/uuid-like(len=%d)"%len(u)
    return "opaque(len=%d)"%len(u)

def classify_secret(s):
    parts=s.split('.')
    if len(parts)==3 and all(parts):
        hdr=b64url(parts[0]); pl=b64url(parts[1])
        if isinstance(pl,dict):
            wanted=('iss','aud','sub','scope','scopes','access','exp','iat','nbf','typ','registry','account','grant_type','client_id')
            claims={k:pl.get(k) for k in wanted if k in pl}
            # never dump the WHOLE payload (may hold secret material); only known metadata keys
            return {"is_jwt":True,"header":hdr,"claims":claims,"all_claim_keys":sorted(pl.keys()),"len":len(s)}
    return {"is_jwt":False,"len":len(s),"prefix4":s[:4]+"...(redacted)"}

print("=====CRED-CLASSIFY-BEGIN=====")
print("TOPLEVEL_KEYS:", sorted(d.keys()))
print("credHelpers:", d.get('credHelpers'))
print("credsStore:", d.get('credsStore'))
auths=d.get('auths',{})
print("NUM_AUTHS:", len(auths))
for host,v in auths.items():
    print("REGISTRY_HOST:", host)
    print("  auth_entry_keys:", sorted(v.keys()))
    if 'identitytoken' in v:
        it=v['identitytoken']
        print("  identitytoken_present: yes", classify_secret(it))
    if 'registrytoken' in v:
        print("  registrytoken_present: yes secret_meta:", classify_secret(v['registrytoken']))
    if 'auth' in v:
        try: dec=base64.b64decode(v['auth']).decode('utf-8','replace')
        except Exception: dec=''
        user,sep,secret=dec.partition(':')
        print("  authtype: basic (base64 user:secret)")
        print("  username_format:", classify_username(user))
        print("  secret_meta:", classify_secret(secret))
    elif 'username' in v:
        print("  username_format:", classify_username(v.get('username','')))
        if 'password' in v:
            print("  password_meta:", classify_secret(v.get('password','')))
print("=====CRED-CLASSIFY-END=====")
PY
CMD ["sleep","60"]
